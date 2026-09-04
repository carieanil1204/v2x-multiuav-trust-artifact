# CMakeLists.txt for SLIC-AODV NS-3 Module
#
# Integration into NS-3 build system.
# Place this file at: ns-3-dev/src/slic-aodv/CMakeLists.txt
#
# Then add 'slic-aodv' to the module list in the top-level CMakeLists.txt
# or run: ./ns3 configure --enable-modules=slic-aodv

build_lib(
  LIBNAME slic-aodv
  SOURCE_FILES
    model/slic-local-graph.cc
    model/slic-centrality.cc
    model/slic-aodv-packet.cc
    model/slic-aodv-routing-protocol.cc
    helper/slic-aodv-helper.cc
  HEADER_FILES
    model/slic-local-graph.h
    model/slic-centrality.h
    model/slic-aodv-packet.h
    model/slic-aodv-routing-protocol.h
    helper/slic-aodv-helper.h
  LIBRARIES_TO_LINK
    ${libinternet}
    ${libwifi}
    ${libmobility}
    ${libnetwork}
    ${libcore}
)
