# Make sure we are running on Ubuntu 18.04
if [[ "$(uname)" != "Linux" ]]; then
    echo "The operating system must be Linux"
    exit 1
fi
if [[ ! "$(lsb_release -d)" =~ "Ubuntu 18.04" ]]; then
    echo "The Linux distribution must be Ubuntu 18.04"
    exit 1
fi

# Update
sudo apt-get update

# Clone the GitHub repo for the P4 compiler
git clone --recursive https://github.com/p4lang/p4c.git

# Install the dependencies
sudo apt-get install -y cmake g++ git automake libtool libgc-dev bison flex libfl-dev libgmp-dev \
                        libboost-dev libboost-iostreams-dev libboost-graph-dev llvm pkg-config \
                        python python-scapy python-ipaddr python-ply tcpdump doxygen graphviz \
                        texlive-full

# Install protobuf 3.6.1 from source code
git clone https://github.com/protocolbuffers/protobuf.git
cd protobuf
git checkout v3.6.1
git submodule update --init --recursive
./autogen.sh
./configure
make
make check
sudo make install
sudo ldconfig

# Build the P4 compiler
cd ~/p4c
mkdir build
cd build
cmake ..
make -j4
make -j4 check

# Install the P4 compiler
sudo make install

# Clone the P4 behavioral model model GitHub repo
cd
git clone https://github.com/p4lang/behavioral-model.git

# Install the dependencies
cd behavioral-model
./install_deps.sh

# Build the software switch
./autogen.sh
./configure
make

# Install the software switch
sudo make install
sudo ldconfig

