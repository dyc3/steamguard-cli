# Maintainer: Carson McManus <carson.mcmanus1@gmail.com>
# Contributor: Mads Mogensen <mads256h at gmail dot com>

_pkgname=steamguard-cli
pkgname=${_pkgname}-git
pkgver=0.14.0.r1.602acc66
pkgrel=1
pkgdesc="A command line utility to generate Steam 2FA codes and respond to confirmations."
arch=('i686' 'x86_64' 'armv6h' 'armv7h')
url="https://github.com/dyc3/steamguard-cli"
license=('GPL3')
makedepends=('rust' 'cargo' 'git')
source=("git+https://github.com/dyc3/steamguard-cli.git")
sha256sums=('SKIP')
options=(!lto)

pkgver() {
    cd "${srcdir}/${_pkgname}"
    git describe --long --tags --match 'v*' | sed 's/\([^-]*-g\)/r\1/;s/-/./g;s/v//g'
}

build() {
    cd "${srcdir}/${_pkgname}"
    cargo build --release
}

package() {
    install -Dm755 "${srcdir}/${_pkgname}/target/release/steamguard" "${pkgdir}/usr/bin/steamguard"
    ln -s "${pkgdir}/usr/bin/steamguard" "${pkgdir}/usr/bin/${_pkgname}"
}
