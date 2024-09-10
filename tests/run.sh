#!/bin/sh
docker run --name dev-ad --hostname ldap.schneide.dev --privileged -p 636:636 -e SMB_ADMIN_PASSWORD=admin123! -v $PWD/:/opt/ad-scripts -v $PWD/samba-data:/var/lib/samba appliedres/dev-ad
