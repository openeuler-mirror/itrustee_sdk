使用说明
1.taconfig.der（证书）和config_cert_private.key（私钥）放入config_cert文件夹下
	=>放置taconfig.der（证书）和config_cert_private.key（私钥）至换当前目录config_cert文件夹下，注意保持文件名一致
	=>taconfig.der（证书）为config证书，该证书应由导入证书CA签发（三方TA），证书内保存的公钥对应私钥为taconfig_key.pem
	=>config_cert_private.key为taconfig.der证书公钥对应私钥，用来对signature段签名
2.TA开发者的证书ta_cert.der放至在ta_cert目录
	=>ta_cert.der证书应至在ta_cert目录，该证书应由导入证书CA签发（三方TA），证书内保存的公钥用来验签TA
3.configs.xml文件放至在input目录
	=>configs.xml保存TA基础信息
4.生成config二进制
	=>所需文件：input/configs.xml、config_cert/taconfig.der、config_cert/config_cert_private.key、ta_cert/ta_cert.der
	=>生成待签名文件data_for_sign： python3 Config_pre.py input/ ${ta_cert_dir}/ta_cert.der ${config_cert_dir}/taconfig.der
	=>生成签名文件data_for_sign.rsa(仅举例)： openssl dgst -sign ${config_cert_dir}/config_cert_private.key -sha256 -out data_for_sign.rsa data_for_sign
	=>生成config（使用公钥）python3 config_v2.py input/ output/ TYPE_PUBKEY
	=>生成config（使用证书）cp ${config_cert_dir}/taconfig.der input/ ; python3 config_v2.py input/ output/ TYPE_CERT
5.config二进制生成在output目录
	=>参考local_sign.sh（包含步骤5中流程）

