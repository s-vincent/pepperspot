Summary:   PepperSpot is a Next Generation Wireless LAN Access Point Controller
Name:      pepperspot
Version:   1.0
Release:   1
URL:       https://svnet.u-strasbg.fr/pepperspot
Source0:   %{name}-%{version}.tar.gz
License:   GPL
Group:     System Environment/Daemons
BuildRoot: %{_tmppath}/%{name}-root

%description 

PepperSpot is a next generation open source captive portal or wireless LAN 
access point controller, which implement the dual stack support (IPv4 and IPv6).
It supports web based login which is today's standard for public HotSpots 
and it supports Wireless Protected Access (WPA) which is the standard of 
the future. Authentication, Authorization and Accounting (AAA) is handled 
by your favorite radius server. Read more on https://svnet.u-strasbg.fr/pepperspot


%prep
%setup -q

%build

./configure --prefix=/usr --enable-static-exec

make

%install

make install prefix=$RPM_BUILD_ROOT/usr
strip $RPM_BUILD_ROOT/usr/sbin/pepper

#Copy pepper init script in place
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
install -m755 doc/pepper.init \
	$RPM_BUILD_ROOT/etc/rc.d/init.d/pepper

#Copy pepper.conf in place
install -m755 doc/pepper.conf \
	$RPM_BUILD_ROOT/etc/pepper.conf

#Clean up unwanted library files
rm -rf $RPM_BUILD_ROOT/usr/include/*
rm -rf $RPM_BUILD_ROOT/usr/lib/*


%clean
rm -rf $RPM_BUILD_ROOT
make clean

%post
/sbin/chkconfig --add pepper

%files
%defattr(-,root,root)

%attr(755, root, root) /usr/sbin/pepper
%attr(755, root, root) /etc/rc.d/init.d/pepper

%doc doc/pepper.conf
%doc doc/pepper.init
%doc doc/pepper.iptables
%doc doc/pepper.ip6tables
%doc doc/hotspotlogin.cgi
%doc doc/dictionary.pepperspot
%doc COPYING

%doc /usr/man/man8/pepper.8.gz

%config /etc/pepper.conf


%changelog
* Thu Mar 25 2004  <support@pepperspot.org>
- Initial release.
