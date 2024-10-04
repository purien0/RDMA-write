#!/bin/bash
modprobe rdma_rxe
rdma link add rxe_0 type rxe netdev ens33
rdma link
ibv_devices


