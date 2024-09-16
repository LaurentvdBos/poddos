CFLAGS = -g -O2 -Wall -Wno-format-truncation -Wno-stringop-truncation
LDLIBS = -lssl -lcrypto -lz

poddos: poddos.o http.o inflate.o truncate.o chunked.o pull.o json.o untar.o layer.o net.o dhcp.o

all: poddos
clean:
	-rm *.o
	-rm poddos
install: poddos poddos@.service
	install poddos /usr/local/bin/
	setcap cap_net_admin+eip /usr/local/bin/poddos
	install --mode=644 --compare poddos@.service /etc/systemd/user/
uninstall:
	-rm /usr/local/bin/poddos
	-rm /etc/systemd/user/poddos@.service
