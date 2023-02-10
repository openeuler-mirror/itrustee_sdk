#!/bin/bash
# make config binary 
# Copyright @ Huawei Technologies Co., Ltd. 2022-2023. All rights reserved.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan
# PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

set -e
# generate and sign the config binary with local private key.

work_dir=$(pwd)
input_dir=${work_dir}/"input"
config_cert_dir=${work_dir}/"config_cert"
ta_cert_dir=${work_dir}/"ta_cert"

# prepare data for been signed.
python3 Config_pre.py input/ ${ta_cert_dir}/ta_cert.der ${config_cert_dir}/taconfig.der

# begin sign.
cd ${input_dir}
if [ ! -f "data_for_sign" ]; then
    echo "can't find data for sign"
    echo "sign fail!"
    exit -1
fi

# config_cert_private.key is the private key of the config certificate.
openssl dgst -sign ${config_cert_dir}/config_cert_private.key -sha256 -sigopt rsa_padding_mode:pss \
    -sigopt rsa_pss_saltlen:-1 -out data_for_sign.rsa data_for_sign

# generate config binary
cd ${work_dir}

if [ -f "${config_cert_dir}/taconfig.der" ]; then
    echo "make config with config cert"
    cp ${config_cert_dir}/taconfig.der ${input_dir}/
    python3 config_v2.py input/ output/ TYPE_CERT
else
    python3 config_v2.py input/ output/ TYPE_PUBKEY
fi

# clean
cd $input_dir
[ -f "$input_dir"/data_for_sign ] && rm data_for_sign
[ -f "$input_dir"/data_for_sign.rsa ] && rm data_for_sign.rsa
[ -f "$input_dir"/configs_tlv ] && rm configs_tlv
[ -f "$input_dir"/*.der ] && rm *.der

if [ "$?" == 0 ]; then
    echo "generate config binary success"
    exit 0
else
    echo "generate config binary failed"
    exit 1
fi
