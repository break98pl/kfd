b:
	xcodebuild clean build CODE_SIGNING_ALLOWED=NO ONLY_ACTIVE_ARCH=NO PRODUCT_BUNDLE_IDENTIFIER=com.opa334.kfd -sdk iphoneos -scheme kfd -configuration Release -derivedDataPath build
	ldid -Skfd/kfd.entitlements build/Build/Products/Release-iphoneos/kfd.app/kfd
	ln -sf build/Build/Products/Release-iphoneos Payload
	zip -r9 kfd.ipa Payload/kfd.app
	rm -rf build

