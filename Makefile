# lalabypass —— roothide / rootless 布局
TARGET := iphone:clang:16.5:15.0
ARCHS := arm64

# 关键：rootless 布局，roothide 的 dpkg 会把 /var/jb 重定向到 .jbroot-*
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = lalabypass
lalabypass_FILES = Tweak.x
lalabypass_FRAMEWORKS = Foundation UIKit CoreLocation
lalabypass_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
