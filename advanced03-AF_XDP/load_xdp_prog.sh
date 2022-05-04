ip link set dev $1 xdpgeneric obj xdp_redirect_kern.o sec xdp

sleep 20

ip link set dev $1 xdpgeneric off
