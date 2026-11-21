# Built inside the VPP source tree: deploy/install/vpp-router-install.sh copies
# this directory to src/plugins/ and adds ipsec_ike_punt to VPP_PLUGINS.
add_vpp_plugin(ipsec_ike_punt
  SOURCES
  ipsec_ike_punt.c
)
