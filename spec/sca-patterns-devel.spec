# spec file for package sca-patterns-devel
#
# Copyright (c) 2020 SUSE LINUX GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

%define base patdev
%define basedir /opt/%{base}

Name:         sca-patterns-devel
Version:      1.0.1
Release:      0
Summary:      Supportconfig Analysis Pattern Development Tools
License:      GPL-2.0-only
URL:          https://github.com/g23guy/sca-patterns-devel
Group:        System/Monitoring
Source:       %{name}-%{version}.tar.gz
Requires:     /usr/bin/git
Requires:     /usr/bin/python
Requires:     /usr/bin/w3m
BuildArch:    noarch

%description
Tools used in the creation and testing of Supportconfig analysis patterns for the SCA Tool.

%prep
%setup -q

%build
#gzip -9f man/*5
#gzip -9f man/*8

%install
pwd;ls -la
#install -d %{buildroot}%{_mandir}/man5
#install -d %{buildroot}%{_mandir}/man8
mkdir -p %{buildroot}%{basedir}/bin
mkdir -p %{buildroot}%{basedir}/patterns
mkdir -p %{buildroot}%{basedir}/forks
mkdir -p %{buildroot}%{_localstatedir}%{basedir}
install -m 555 bin/* %{buildroot}%{basedir}/bin
#install -m 644 man/*.5.gz %{buildroot}%{_mandir}/man5
#install -m 644 man/*.8.gz %{buildroot}%{_mandir}/man8

%files
%defattr(-,root,root,-)
%dir %{basedir}
%dir %{_localstatedir}%{basedir}
%{basedir}/*
%attr(775,root,users) %{basedir}/forks
#%doc %{_mandir}/man5/*
#%doc %{_mandir}/man8/*

%post
ln -s -f %{basedir}/bin/pat /usr/local/bin
ln -s -f %{basedir}/bin/gitpatterns /usr/local/bin
ln -s -f %{basedir}/bin/chktid /usr/local/bin
ln -s -f %{basedir}/bin/gvc /usr/local/bin

%postun
rm -f /usr/local/bin/pat
rm -f /usr/local/bin/gitpatterns
rm -f /usr/local/bin/chktid
rm -f /usr/local/bin/gvc

%changelog

