# BUILDING
Builds entirely on Ubuntu 22.04. Install `build-essential`  
Install LLVM-20 with `llvm.sh 20 all` from `https://apt.llvm.org/llvm.sh`  
Install latest golang.  
Run `make`  

## Windows SDK Linux Setup
This is a little trick to get around windows builds needing a case-insensitive 
file system for the WinSDK.
- First create a sparse image file  
  `dd if=/dev/zero of=WDK.img bs=1 count=0 seek=20G`
- Create a case-insensitive enabled ext4 on it  
  `mkfs -t ext4 -O casefold -E encoding_flags=strict WDK.img`
- Mount it to the dir  
  `sudo mount WDK.img /opt/WDK && sudo chmod 777 /opt/WDK`
- Create a case insensitive dir  
  `mkdir /opt/WDK/WinSDK && chattr +F /opt/WDK/WinSDK`
- Use [vsdownload.py](https://gist.githubusercontent.com/Danukeru/e5e7cf6050519551844a3134cfa9a23c/raw/fa06e2104d82ee14eef3799a3a8e784bce9460a2/vsdownload.py) to pull down the latest SDK  
   `python3 vsdownload.py --dest /opt/WDK/WinSDK`
- Update the paths and versions in [config.cmake](https://github.com/Danukeru/KLINIKAL/blob/master/demo/cmake/clang-windows/config.cmake)
