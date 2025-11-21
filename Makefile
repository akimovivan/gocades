all: build

build-lib:
	cd signer && g++ -DUNIX -std=c++11 -fPIC -shared -o libsigner.so src/libsigner.cpp \
    	-I/opt/cprocsp/include/pki -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include \
    	-L/opt/cprocsp/lib/amd64 -lcades -lcapi20 -lcapi10 -lrdrsup

build: build-lib
	CGO_ENABLED=1 go build -o gocades 

run: build
	./gocades

clean:
	rm -f gocades || echo "no binary"
