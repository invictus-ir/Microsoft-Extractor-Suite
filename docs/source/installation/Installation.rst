Installation
=======

Install the Powershell module ExchangeOnlineManagement:
::

   install-module -name ExchangeOnlineManagement

Install the Powershell module AzureADPreview:
::

   Install-Module -Name AzureADPreview

.. note::

   If you receive an error message indicating that the specified commands already exist on your system, you can resolve the issue by including the "-AllowClobber" parameter in the "Install-Module" command. This parameter will allow the installation process to overwrite any existing versions of the module and replace them with the newer version.

Getting Started
-------
To get started with the Microsoft-Extractor-Suite tool, make sure the requirements are met.

The first step is to import the Microsoft-Extractor-Suite:
::

   Import-Module .\Microsoft-Extractor-Suite.psd1

Additionally, you must sign-in to Microsoft 365 or Azure depending on your usage before Microsoft-Extractor-Suite functions are made available. To sign in, use the cmdlets:
::

   Connect-M365
   Connect-Azure
