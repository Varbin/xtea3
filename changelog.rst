Changelog
---------

Version 0.3.2; Jul 30, 2015
~~~~~~~~~~~~~~~~~~~~~~~~~~~

[0.3.2] Fixed installer

Version 0.3.1; Oct 30, 2014
~~~~~~~~~~~~~~~~~~~~~~~~~~~

[0.3.1] Fixed #1: TypeError on windows 7 and python 3.4

Version 0.3.1; Oct 30, 2014
~~~~~~~~~~~~~~~~~~~~~~~~~~~

[0.3.1] Fixed #1: TypeError on windows 7 and python 3.4

Version 0.3.0; Jul 18, 2014
~~~~~~~~~~~~~~~~~~~~~~~~~~~

[0.3.0] Fixed CBCMAC

 - Fixed CBCMAC implementation
 - Added documentation

 
Version 0.2.0; Jul 18, 2014
~~~~~~~~~~~~~~~~~~~~~~~~~~~

[0.2.0] CBC, CFB, CTR | added CBCMAC

 - Added CBC, CFB, CTR and CBCMAC
 - Raises a NonImplementedError on other modes (PGP, unofficial CCM and others)

 
Version 0.1.1; Long ago...
~~~~~~~~~~~~~~~~~~~~~~~~~~

[0.1.1] NotImplementedError on CFB

 - Module raises a NotImplementedError on CFB
 - Minor changes

 
Version 0.1; Jun 22, 2014
~~~~~~~~~~~~~~~~~~~~~~~~~

[0.1] Initial release

 - Supports all mode except CFB
 - Buggy CTR ( "ß" = "\\xc3\\x9f" )
 - Working with PEP 272, default mode is ECB
