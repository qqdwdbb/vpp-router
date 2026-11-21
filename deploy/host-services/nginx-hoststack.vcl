vcl {
  heapsize 64M
  segment-size 67108864
  add-segment-size 67108864
  rx-fifo-size 1048576
  tx-fifo-size 1048576
  app-socket-api /run/vpp/app_ns_sockets/default
  app-scope-global
  use-mq-eventfd
}
