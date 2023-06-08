wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.3.1.tar.gz
tar -zxf v4.3.1.tar.gz && cd yara-4.3.1

sudo apt-get install automake libtool make gcc pkg-config mingw-w64
./bootstrap.sh && ./configure && make && sudo make install
sudo ldconfig

cd $OLDPWD

GOOS=linux GOARCH=amd64 go build && mv GoReSym GoReSym_lin

cd yara-4.3.1
YARA_SRC=$(pwd)

make clean
./configure --host=x86_64-w64-mingw32 --disable-magic --disable-cuckoo --without-crypto --prefix=${YARA_SRC}/x86_64-w64-mingw32
make -C ${YARA_SRC}
sudo make -C ${YARA_SRC} install
cd $OLDPWD

go get -d -u github.com/hillu/go-yara/v4
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc PKG_CONFIG_PATH=${YARA_SRC}/x86_64-w64-mingw32/lib/pkgconfig go install -ldflags '-extldflags "-static"' github.com/hillu/go-yara/v4
GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc CGO_ENABLED=1 go build --ldflags '-extldflags "-lm -static"' && mv GoReSym.exe GoReSym_win64.exe

sudo rm -rf yara-4.3.1
rm v4.3.1.tar.gz