# burp-pdf2txt

This burp extension will look the body of every server answers to check if it contains a PDF. 
In such case, it will then perform a pdf2txt transformation and update the content-length accordingly.
This could be useful for quickly reviewing PDF, using burp search filters to find data in those pdf or attacking PDF generators.

Take heed that it will perform the transformation on every requests sent through Burp.
