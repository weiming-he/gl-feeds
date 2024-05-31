#
# Copyright (C) 2021 CZ.NIC, z. s. p. o. (https://www.nic.cz/)
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=ctrld
PKG_VERSION:=1.3.6
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/Control-D-Inc/ctrld
PKG_SOURCE_VERSION:=v$(PKG_VERSION)
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz

PKG_LICENSE:=BSD-3-Clause
PKG_LICENSE_FILES:=LICENSE

GO_PKG:=github.com/Control-D-Inc/ctrld
GO_PKG_LDFLAGS_X:=main.version=v$(PKG_VERSION)

PKG_BUILD_DIR:=$(BUILD_DIR)/ctrld-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/ctrld
	SECTION:=net
	CATEGORY:=Network
	TITLE:=ctrld
	URL:=https://ctrld.com
	DEPENDS:=$(GO_ARCH_DEPENDS) +ca-bundle +kmod-tun
endef

define Package/ctrld/description
	It creates a secure network between your servers, computers,
	and cloud instances. Even when separated by firewalls or subnets.
endef


define Package/ctrld/install
	$(call GoPackage/Package/Install/Bin,$(1))
endef

$(eval $(call GoBinPackage,ctrld))
$(eval $(call BuildPackage,ctrld))
