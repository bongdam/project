
#!/bin/sh
  
PROFILE_NAME_=`ls CURRENT_PROFILE_*`
PROFILE_NAME=${PROFILE_NAME_#CURRENT_PROFILE_}

#echo "Copy DTB files to the common/build/ipq/ directory"
#rm -rf ./firmware_image/common/build/ipq/qcom-ipq8064-*
#cp ./bin/ipq806x/dtbs/qcom-ipq8064-* firmware_image/common/build/ipq
echo "Copy the openwrt* images built to the common/build/ipq folder"
rm -rf ./firmware_image/common/build/ipq/openwrt*
cp ./bin/ipq806x/openwrt* firmware_image/common/build/ipq
  
pushd firmware_image/common/build
echo "create single image"
python update_common_info.py
popd
  
. davo/${PROFILE_NAME}/version.mk
. davo/buildtime.mk
  
#cp ./firmware_image/common/build/bin/nand-ipq40xx-single.img ./bin/ipq806x/
#cp ./firmware_image/common/build/bin/nor-ipq40xx-single.img ./bin/ipq806x/
#cp ./firmware_image/common/build/bin/ipq40xx-nornand-apps.img ./bin/ipq806x/
#cp ./firmware_image/common/build/bin/nornand-ipq40xx-single.img ./bin/ipq806x/

. davo/${PROFILE_NAME}/version.mk
. davo/buildtime.mk

cp ./firmware_image/common/build/bin/nornand-ipq40xx-single.img ./bin/ipq806x/
cp ./firmware_image/common/build/bin/nornand-ipq40xx-single.img ./bin/ipq806x/${MODEL}_${MAJOR}.${MINOR}.${BUILD}_${BUILD_TIME}_${REVISION}_single_raw.img

cp ./firmware_image/common/build/bin/ipq40xx-nornand-apps.img ./bin/ipq806x/
cp ./firmware_image/common/build/bin/ipq40xx-nornand-apps.img ./bin/ipq806x/${MODEL}_${MAJOR}.${MINOR}.${BUILD}_${BUILD_TIME}-${REVISION}_raw.img

dv_hosttools/dvct ./bin/ipq806x/${MODEL}_${MAJOR}.${MINOR}.${BUILD}_${BUILD_TIME}_${REVISION}_single_raw.img ./bin/ipq806x/${MODEL}_${MAJOR}.${MINOR}.${BUILD}_${BUILD_TIME}_${REVISION}_single.img ${PRODUCT_CODE} ${MAJOR} ${MINOR} ${BUILD}
dv_hosttools/dvct ./bin/ipq806x/${MODEL}_${MAJOR}.${MINOR}.${BUILD}_${BUILD_TIME}-${REVISION}_raw.img ./bin/ipq806x/${MODEL}_${MAJOR}.${MINOR}.${BUILD}_${BUILD_TIME}-${REVISION}.img ${PRODUCT_CODE} ${MAJOR} ${MINOR} ${BUILD}

dv_hosttools/dvct ./bin/ipq806x/${MODEL}_${MAJOR}.${MINOR}.${BUILD}_${BUILD_TIME}-${REVISION}_raw.img ./bin/ipq806x/${MODEL}_${MAJOR}.${MINOR}.${BUILD}_${BUILD_TIME}-${REVISION}_COMPATIBLE.img ${PRODUCT_COMPATIBLE_CODE} ${MAJOR} ${MINOR} ${BUILD}

echo "./bin/ipq806x/${MODEL}_${MAJOR}.${MINOR}.${BUILD}_${BUILD_TIME}_${REVISION}_single.img" generated
echo "./bin/ipq806x/${MODEL}_${MAJOR}.${MINOR}.${BUILD}_${BUILD_TIME}-${REVISION}.img" generated
