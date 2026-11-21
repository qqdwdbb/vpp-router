// SPDX-License-Identifier: GPL-2.0-only
/* N1-only experimental bridge: Linux owns platform power/PHY setup;
 * a single userspace file owns all packet descriptors and DMA while open.
 * No hot-unbind, suspend, netns migration or device removal is supported. */
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/capability.h>
#include <linux/of_address.h>
#include <linux/dma-mapping.h>
#include <linux/pm_runtime.h>
#include <linux/phy.h>
#include <linux/iopoll.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/bitmap.h>
#include <linux/linkmode.h>
#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/of_irq.h>
#include <linux/eventfd.h>
#include <linux/spinlock.h>
#include "n1_dma.h"

static struct net_device *ndev;
static struct device *dev;
static struct phy_device *phy;
static __ETHTOOL_DECLARE_LINK_MODE_MASK(saved_advertising);
static void __iomem *regs;
static phys_addr_t reg_phys;
static void *arena;
static dma_addr_t arena_dma;
static bool claimed, was_up, pm_held, poisoned;
static DEFINE_MUTEX(owner_lock);
#define N1_DMA_LINE 64 /* S905D Cortex-A53 D-cache line */
struct pinned_page {
    struct page *page;
    dma_addr_t dma;
    unsigned long address;
    DECLARE_BITMAP(device_lines, PAGE_SIZE / N1_DMA_LINE);
};
static struct pinned_page *pages;
static unsigned int pinned_count;
module_param_named(pinned_pages, pinned_count, uint, 0444);
module_param_named(poisoned, poisoned, bool, 0444);
static struct mm_struct *owner_mm;
/* N1_SYNC is serialized by owner_lock. Never allocate on the packet path. */
static struct n1_sync sync_request;
#define N1_RX_IRQ (0x10000u | 0x40u)
static DEFINE_SPINLOCK(irq_lock);
static struct eventfd_ctx *irq_event;
static int irq_number = -1;

static irqreturn_t n1_interrupt(int irq, void *data)
{
    unsigned long flags;
    u32 status;
    spin_lock_irqsave(&irq_lock, flags);
    status = readl(regs + 0x1014);
    if (!(readl(regs + 0x101c) & 0x40) || !(status & 0x40)) {
        spin_unlock_irqrestore(&irq_lock, flags);
        return IRQ_NONE;
    }
    writel(0, regs + 0x101c);
    writel(N1_RX_IRQ, regs + 0x1014);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
    eventfd_signal(irq_event);
#else
    eventfd_signal(irq_event, 1);
#endif
    spin_unlock_irqrestore(&irq_lock, flags);
    return IRQ_HANDLED;
}

static void n1_irq_mask(void)
{
    unsigned long flags;
    spin_lock_irqsave(&irq_lock, flags);
    writel(0, regs + 0x101c);
    spin_unlock_irqrestore(&irq_lock, flags);
    if (irq_number >= 0)
        synchronize_irq(irq_number);
}

static int n1_irq_setup(int fd)
{
    struct eventfd_ctx *event;
    int irq, err;
    if (irq_event)
        return -EBUSY;
    event = eventfd_ctx_fdget(fd);
    if (IS_ERR(event))
        return PTR_ERR(event);
    irq = of_irq_get_byname(dev->of_node, "macirq");
    if (irq < 0) {
        err = irq;
        goto put_event;
    }
    irq_event = event;
    err = request_irq(irq, n1_interrupt, IRQF_SHARED, "n1-dwmac", &irq_number);
    if (err) {
        irq_event = NULL;
        goto put_event;
    }
    irq_number = irq;
    return 0;
put_event:
    eventfd_ctx_put(event);
    return err;
}

static void n1_irq_free(void)
{
    if (irq_number < 0)
        return;
    n1_irq_mask();
    free_irq(irq_number, &irq_number);
    irq_number = -1;
    eventfd_ctx_put(irq_event);
    irq_event = NULL;
}

/* Only call after a successful reset: no descriptor can still reference pages. */
static void unmap_user_pages(void)
{
    while (pinned_count) {
        struct pinned_page *p = &pages[--pinned_count];
        /* Crash-path may not have updated device_lines. Always return the
         * whole page to the CPU before unpin. */
        dma_sync_single_range_for_cpu(dev, p->dma, 0, PAGE_SIZE,
                                       DMA_BIDIRECTIONAL);
        dma_unmap_page_attrs(dev, p->dma, PAGE_SIZE, DMA_BIDIRECTIONAL,
                             DMA_ATTR_SKIP_CPU_SYNC);
        unpin_user_pages_dirty_lock(&p->page, 1, true);
    }
}

static long map_user_page(unsigned long arg)
{
    struct n1_page request;
    struct page *page;
    dma_addr_t dma;
    long err;
    unsigned int i;
    if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
        return -EFAULT;
    if (request.address != (unsigned long)request.address ||
        !IS_ALIGNED(request.address, PAGE_SIZE) || request.pad)
        return -EINVAL;
    for (i = 0; i < pinned_count; i++)
        if (pages[i].address == request.address)
            goto found;
    if (pinned_count == N1_MAX_PAGES)
        return -ENOSPC;
    err = pin_user_pages_fast(request.address, 1, FOLL_WRITE | FOLL_LONGTERM, &page);
    if (err != 1)
        return err < 0 ? err : -EFAULT;
    /* Refuse aliases: mapping an already-live DMA page twice obscures ownership. */
    for (i = 0; i < pinned_count; i++)
        if (pages[i].page == page) { unpin_user_page(page); return -EINVAL; }
    dma = dma_map_page_attrs(dev, page, 0, PAGE_SIZE, DMA_BIDIRECTIONAL,
                             DMA_ATTR_SKIP_CPU_SYNC);
    if (dma_mapping_error(dev, dma)) { unpin_user_page(page); return -EIO; }
    if ((u64)dma + PAGE_SIZE - 1 > U32_MAX ||
        dma != page_to_phys(page)) {
        /* This N1 implementation requires direct DMA, never a bounce buffer. */
        dma_unmap_page_attrs(dev, dma, PAGE_SIZE, DMA_BIDIRECTIONAL,
                             DMA_ATTR_SKIP_CPU_SYNC);
        unpin_user_page(page);
        return -ERANGE;
    }
    i = pinned_count++;
    pages[i] = (struct pinned_page){ .page = page, .dma = dma,
                                   .address = request.address };
found:
    request.id = i; request.dma = pages[i].dma;
    return copy_to_user((void __user *)arg, &request, sizeof(request)) ? -EFAULT : 0;
}

static long sync_user_pages(unsigned long arg)
{
    struct n1_sync *request = &sync_request;
    unsigned int i;
    long err = 0;
    if (copy_from_user(request, (void __user *)arg,
                       offsetof(struct n1_sync, ranges)))
        return -EFAULT;
    if (!request->count || request->count > N1_SYNC_BATCH || request->for_cpu > 1) {
        err = -EINVAL; goto out;
    }
    if (copy_from_user(request->ranges,
                       (char __user *)arg + offsetof(struct n1_sync, ranges),
                       request->count * sizeof(request->ranges[0])))
        return -EFAULT;
    /* Validate the entire batch before changing any ownership. */
    for (i = 0; i < request->count; i++) {
        struct n1_range *r = &request->ranges[i];
        if (r->id >= pinned_count || r->pad || !r->length ||
            r->offset >= PAGE_SIZE || r->length > PAGE_SIZE - r->offset) {
            err = -EINVAL; goto out;
        }
    }
    for (i = 0; i < request->count; i++) {
        struct n1_range *r = &request->ranges[i];
        if (request->for_cpu)
            dma_sync_single_range_for_cpu(dev, pages[r->id].dma, r->offset,
                                           r->length, DMA_BIDIRECTIONAL);
        else
            dma_sync_single_range_for_device(dev, pages[r->id].dma, r->offset,
                                              r->length, DMA_BIDIRECTIONAL);
        if (request->for_cpu)
            bitmap_clear(pages[r->id].device_lines, r->offset / N1_DMA_LINE,
                         DIV_ROUND_UP(r->offset % N1_DMA_LINE + r->length, N1_DMA_LINE));
        else
            bitmap_set(pages[r->id].device_lines, r->offset / N1_DMA_LINE,
                       DIV_ROUND_UP(r->offset % N1_DMA_LINE + r->length, N1_DMA_LINE));
    }
out:
    return err;
}

static int halt_dma(void)
{
    u32 value;
    n1_irq_mask();
    writel(readl(regs + 0x1018) & ~0x2002, regs + 0x1018);
    writel(readl(regs) & ~0x0c, regs);
    /* Reset must complete before any arena reuse/free or Linux restart. */
    writel(readl(regs + 0x1000) | 1, regs + 0x1000);
    if (readl_poll_timeout(regs + 0x1000, value, !(value & 1), 10, 100000)) {
        if (!poisoned) {
            poisoned = true;
            __module_get(THIS_MODULE); /* pin arena/device/power until reboot */
        }
        pr_err("n1_dma: DMA reset failed; resources pinned, reboot required\n");
        return -ETIMEDOUT;
    }
    writel(0, regs + 0x100c);
    writel(0, regs + 0x1010);
    return 0;
}

static int net_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
    if (netdev_notifier_info_to_dev(ptr) == ndev &&
        event == NETDEV_PRE_UP && READ_ONCE(claimed))
        return notifier_from_errno(-EBUSY);
    return NOTIFY_DONE;
}
static struct notifier_block net_notifier = { .notifier_call = net_event };

static void restore_linux(void)
{
    if (phy) {
        linkmode_copy(phy->advertising, saved_advertising);
        phy_suspend(phy);
        put_device(&phy->mdio.dev);
        phy = NULL;
    }
    rtnl_lock();
    WRITE_ONCE(claimed, false);
    if (was_up && dev_open(ndev, NULL))
        pr_err("n1_dma: eth0 reopen failed; check kernel log\n");
    rtnl_unlock();
    if (pm_held) {
        pm_runtime_put(dev);
        pm_held = false;
    }
}

static int n1_open(struct inode *inode, struct file *file)
{
    int err;
    if (!capable(CAP_SYS_RAWIO))
        return -EPERM;
    mutex_lock(&owner_lock);
    if (claimed || poisoned) {
        err = -EBUSY;
        goto out;
    }
    rtnl_lock();
    was_up = !!(ndev->flags & IFF_UP);
    /* Existing Linux setup is required to obtain an initialized PHY. */
    if (!was_up || !ndev->phydev) {
        err = -ENETDOWN;
        rtnl_unlock();
        goto out;
    }
    phy = ndev->phydev;
    linkmode_copy(saved_advertising, phy->advertising);
    get_device(&phy->mdio.dev);
    err = pm_runtime_resume_and_get(dev);
    if (err < 0) {
        put_device(&phy->mdio.dev);
        phy = NULL;
        rtnl_unlock();
        goto out;
    }
    pm_held = true;
    WRITE_ONCE(claimed, true);
    dev_close(ndev); /* synchronously stop NAPI/IRQs and free Linux rings */
    rtnl_unlock();
    /* phy_detach() asserts the PHY reset GPIO. Resume alone does not
     * deassert it; recreate board-specific PHY initialization first. */
    err = phy_init_hw(phy);
    if (!err)
        err = phy_resume(phy);
    if (!err)
        linkmode_set_pause(phy->advertising, true, true);
    if (!err)
        err = phy_start_aneg(phy);
    if (!err)
        err = halt_dma();
    if (err) {
        if (!poisoned)
            restore_linux();
        goto out;
    }
    memset(arena, 0, N1_ARENA);
    owner_mm = current->mm;
    mmgrab(owner_mm); /* retain mm_struct, not mm_users/VMA/file references */
out:
    mutex_unlock(&owner_lock);
    return err;
}

static int n1_release(struct inode *inode, struct file *file)
{
    int err;
    mutex_lock(&owner_lock);
    n1_irq_free();
    err = halt_dma();
    if (!err) {
        unmap_user_pages();
        if (owner_mm) { mmdrop(owner_mm); owner_mm = NULL; }
        restore_linux();
    }
    mutex_unlock(&owner_lock);
    return err;
}

static long n1_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct n1_info info = {
        .abi = N1_ABI, .arena_size = N1_ARENA,
        .regs_size = N1_REG_SIZE, .ring_size = N1_RING,
        .dma_base = arena_dma,
        .page_size = PAGE_SIZE, .cache_align = dma_get_cache_alignment(),
    };
    struct n1_link link = {0};
    int err;
    if (cmd == N1_IRQ_SETUP || cmd == N1_IRQ_ENABLE || cmd == N1_IRQ_DISABLE) {
        unsigned long flags;
        int fd;
        mutex_lock(&owner_lock);
        if (poisoned || current->mm != owner_mm)
            err = -EPERM;
        else if (cmd == N1_IRQ_SETUP) {
            if (copy_from_user(&fd, (void __user *)arg, sizeof(fd)))
                err = -EFAULT;
            else
                err = n1_irq_setup(fd);
        } else if (!irq_event)
            err = -ENODEV;
        else {
            spin_lock_irqsave(&irq_lock, flags);
            writel(0, regs + 0x101c);
            if (cmd == N1_IRQ_ENABLE) {
                writel(N1_RX_IRQ, regs + 0x1014);
                writel(N1_RX_IRQ, regs + 0x101c);
            }
            spin_unlock_irqrestore(&irq_lock, flags);
            err = 0;
        }
        mutex_unlock(&owner_lock);
        return err;
    }
    if (cmd == N1_MAP_PAGE || cmd == N1_SYNC || cmd == N1_UNMAP_ALL) {
        long result;
        mutex_lock(&owner_lock);
        if (poisoned || current->mm != owner_mm)
            result = -EPERM;
        else if (cmd == N1_UNMAP_ALL) {
            result = halt_dma();
            if (!result) unmap_user_pages();
        } else
            result = cmd == N1_MAP_PAGE ? map_user_page(arg) : sync_user_pages(arg);
        mutex_unlock(&owner_lock);
        return result;
    }
    if (cmd == N1_INFO) {
        memcpy(info.mac, ndev->dev_addr, ETH_ALEN);
        return copy_to_user((void __user *)arg, &info, sizeof(info)) ? -EFAULT : 0;
    }
    if (cmd == N1_STOP)
        return halt_dma();
    if (cmd != N1_LINK)
        return -ENOTTY;
    mutex_lock(&phy->lock);
    err = phy_read_status(phy);
    if (!err) {
        bool tx_pause, rx_pause;
        link.up = phy->link;
        link.speed = phy->speed > 0 ? phy->speed : 0;
        link.full_duplex = phy->duplex == DUPLEX_FULL;
        phy_get_pause(phy, &tx_pause, &rx_pause);
        link.pause = (rx_pause ? N1_PAUSE_RX : 0) |
                     (tx_pause ? N1_PAUSE_TX : 0);
    }
    mutex_unlock(&phy->lock);
    if (err)
        return err;
    return copy_to_user((void __user *)arg, &link, sizeof(link)) ? -EFAULT : 0;
}

static int n1_mmap(struct file *file, struct vm_area_struct *vma)
{
    unsigned long length = vma->vm_end - vma->vm_start;
    if (!(vma->vm_flags & VM_SHARED) || (vma->vm_flags & VM_EXEC))
        return -EINVAL;
    /* vm_file pins the exclusive file, module and DMA lifetime across mmap/fork. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
    vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP | VM_DONTCOPY);
#else
    vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP | VM_DONTCOPY;
#endif
    if (vma->vm_pgoff == 0 && length == PAGE_ALIGN(N1_REG_SIZE)) {
        vma->vm_page_prot = pgprot_device(vma->vm_page_prot);
        return vm_iomap_memory(vma, reg_phys, N1_REG_SIZE);
    }
    if (vma->vm_pgoff != 1 || length != PAGE_ALIGN(N1_ARENA))
        return -EINVAL;
    vma->vm_pgoff = 0;
    return dma_mmap_coherent(dev, vma, arena, arena_dma, N1_ARENA);
}
static const struct file_operations fops = {
    .owner = THIS_MODULE, .open = n1_open, .release = n1_release,
    .unlocked_ioctl = n1_ioctl, .mmap = n1_mmap,
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
    .llseek = no_llseek,
#endif
    /* 6.12 起没有 no_llseek：不设置 llseek 时 open 清除 FMODE_LSEEK，lseek 同样返回 -ESPIPE */
};
static struct miscdevice misc = {
    .minor = MISC_DYNAMIC_MINOR, .name = "n1-dwmac", .fops = &fops, .mode = 0600,
};

static int __init n1_init(void)
{
    struct resource res;
    int err;
    ndev = dev_get_by_name(&init_net, "eth0");
    if (!ndev)
        return -ENODEV;
    dev = ndev->dev.parent;
    if (!dev || !dev->of_node ||
        !of_machine_is_compatible("phicomm,n1") ||
        !of_device_is_compatible(dev->of_node, "snps,dwmac-3.70a")) {
        err = -ENODEV;
        goto net_put;
    }
    err = of_address_to_resource(dev->of_node, 0, &res);
    if (err || resource_size(&res) < N1_REG_SIZE) {
        err = -ENODEV;
        goto net_put;
    }
    reg_phys = res.start;
    regs = ioremap(reg_phys, N1_REG_SIZE);
    if (!regs) {
        err = -ENOMEM;
        goto net_put;
    }
    arena = dma_alloc_coherent(dev, N1_ARENA, &arena_dma, GFP_KERNEL);
    if (!arena) {
        err = -ENOMEM;
        goto unmap;
    }
    if ((u64)arena_dma + N1_ARENA - 1 > U32_MAX) {
        err = -ERANGE;
        goto free_dma;
    }
    pages = kcalloc(N1_MAX_PAGES, sizeof(*pages), GFP_KERNEL);
    if (!pages) { err = -ENOMEM; goto free_dma; }
    err = register_netdevice_notifier(&net_notifier);
    if (err)
        goto free_dma;
    err = misc_register(&misc);
    if (err) {
        unregister_netdevice_notifier(&net_notifier);
        goto free_dma;
    }
    pr_info("n1_dma: ready, DMA=%pad bytes=%u; eth0 claimed only on open\n",
            &arena_dma, N1_ARENA);
    return 0;
free_dma:
    kfree(pages);
    dma_free_coherent(dev, N1_ARENA, arena, arena_dma);
unmap:
    iounmap(regs);
net_put:
    dev_put(ndev);
    return err;
}
static void __exit n1_exit(void)
{
    misc_deregister(&misc);
    unregister_netdevice_notifier(&net_notifier);
    dma_free_coherent(dev, N1_ARENA, arena, arena_dma);
    kfree(pages);
    iounmap(regs);
    dev_put(ndev);
}
module_init(n1_init);
module_exit(n1_exit);
MODULE_LICENSE("GPL");
MODULE_INFO(n1_dma_abi, "3");
MODULE_DESCRIPTION("N1 experimental exclusive DWMAC MMIO and coherent DMA bridge");
