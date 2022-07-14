1.TA Signature Packing Preparation Materials, and put these files to build/pack-TA/input folder:
1).libcombine.so TA compilation product
2).manifest.txt Basic TA configuration information
3).config.mk file

2.Generate rsa key pair by cmd:openssl genrsa -out private_key.pem 4096,
then put this file to build/signtools/TA_cert/, file name must be private_key.pem.

3.Apply for the TA config certificate from the Huawei contact person, then put this file to
build/signtools/signed_config/, file name must be config.

4.Run build_TA_Linux_release.sh script. Obtain the signed TA product sec file from build/pack-TA/output folder.