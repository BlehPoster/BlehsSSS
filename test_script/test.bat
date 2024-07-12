MKDIR data

rem create shares
..\out\Debug\cli.exe sss-share --secret="hallo world" --shares=5 --min=2 --out=data\shares.dat
rem recreate to check if the shares are valid
..\out\Debug\cli.exe sss-recreate --out=data\shares.dat

rem create account bleh
..\out\Debug\cli.exe account-create --name=bleh --out=data\blehsss-account-bleh.dat
rem create account blah
..\out\Debug\cli.exe account-create --name=blah --out=data\blehsss-account-blah.dat

rem export and verify account bleh
..\out\Debug\cli.exe account-public-export --account=data\blehsss-account-blah.dat --out=data\blehsss-account-public-blah.dat
..\out\Debug\cli.exe account-public-verify --public=data\blehsss-account-public-blah.dat

rem export and verify account blah
..\out\Debug\cli.exe account-public-export --account=data\blehsss-account-bleh.dat --out=data\blehsss-account-public-bleh.dat
..\out\Debug\cli.exe account-public-verify --public=data\blehsss-account-public-bleh.dat

rem encrypt share for account blah
..\out\Debug\cli.exe transportable-share --public-part=data\blehsss-account-public-blah.dat --share-file=data\shares.dat --share-number=1 --account=data\blehsss-account-bleh.dat --out=data\encrypted-share-bleh.dat

rem decrypt share for account blah
..\out\Debug\cli.exe share_print --share-file=data\encrypted-share-bleh.dat --account=data\blehsss-account-blah.dat