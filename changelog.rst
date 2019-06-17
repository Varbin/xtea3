Changelog
---------

Version 1.0.0; Jun 17, 2019
~~~~~~~~~~~~~~~~~~~~~~~~~~~

 - xtea3 is now a wrapper around `xtea>=0.6`
 - Removal of CBCMAC (security reasons)
 - For more changes, see changelog of xtea_.
 - Removal of test(), a better self test will be implemented.
 - Removal of the nonstandard `support`constant.

.. _xtea: https://pypi.org/project/xtea

Version 0.3.2; Jul 30, 2015
~~~~~~~~~~~~~~~~~~~~~~~~~~~

 - Fixed installer

Version 0.3.1; Oct 30, 2014
~~~~~~~~~~~~~~~~~~~~~~~~~~~

 - Fixed #1: TypeError on windows 7 and python 3.4

Version 0.3.0; Jul 18, 2014
~~~~~~~~~~~~~~~~~~~~~~~~~~~

 - Fixed CBCMAC implementation
 - Added documentation

 
Version 0.2.0; Jul 18, 2014
~~~~~~~~~~~~~~~~~~~~~~~~~~~

 - Added CBC, CFB, CTR and CBCMAC
 - Raises a NonImplementedError on other modes (PGP, unofficial CCM and others)

 
Version 0.1.1; Long ago...
~~~~~~~~~~~~~~~~~~~~~~~~~~

 - Module raises a NotImplementedError on CFB
 - Minor changes

 
Version 0.1; Jun 22, 2014
~~~~~~~~~~~~~~~~~~~~~~~~~

 - Initial release
 - Supports all mode except CFB
 - Buggy CTR ( "ß" = "\\xc3\\x9f" )
 - Working with PEP 272, default mode is ECB
