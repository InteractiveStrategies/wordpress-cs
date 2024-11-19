# Interactive Strategies WordPress coding standards

This package defines customized Code Sniffer rules for WordPress projects. It is primarily based on [WordPress](https://github.com/WordPress/WordPress-Coding-Standards) , with some sniffs excluded and others downgraded to warnings. Some additional sniffs not provided have also been added.

## Installing the ruleset

Use Composer to install the ruleset and its dependencies as a package:

`composer require --dev interactivestrategies/wordpress-cs`

## Making the IS rules the default for your project

Add a phpcs.xml.dist file in your project with content like this(make sure to replace the path with the correct theme file name):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ruleset name="IS WordPress Standards">
    <rule ref="ISWordPress"/>

    <file>web/app/themes/emperor</file>

</ruleset>
```

The <file> tag(s) define what paths the rules should be applied to/within.
