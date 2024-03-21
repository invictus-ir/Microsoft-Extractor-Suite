E-mails/Attachments
=======
This section comprises a variety of functions designed to gather e-mails and their attachments. 

.. note::

  **Important note** The following functions require the 'Mail.ReadBasic.All' scope which is an application-level permission, requiring an application-based connection through the 'Connect-MgGraph' command for its use. 

Get a specific email.
^^^^^^^^^^^
Get a specific email based on userId and Internet Message Id and saves the output to a msg or txt file.

Usage
""""""""""""""""""""""""""
Retrieves an email from fortunahodan@bonacu.onmicrosoft.com with the internet message identifier <d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com> to a msg file.
::

   Get-Email -userIds fortunahodan@bonacu.onmicrosoft.com -internetMessageId "<d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com>" 

Retrieves an email and the attachment from fortunahodan@bonacu.onmicrosoft.com with the internet message identifier <d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com> to a msg file.
::

   Get-Email -userIds fortunahodan@bonacu.onmicrosoft.com -internetMessageId "<d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com>" -attachment True

Retrieves an email and saves it to C:\\Windows\\Temp folder.	
::

   Get-Email -userIds fortunahodan@bonacu.onmicrosoft.com -internetMessageId "<d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com>" -OutputDir C:\Windows\Temp

Parameters
""""""""""""""""""""""""""
-UserIds (Mandatory)
    - The unique identifier of the user.

-InternetMessageId (Mandatory)
    - The InternetMessageId parameter represents the Internet message identifier of an item.

-Output (optional)
    - Output is the parameter specifying the msg or txt output type.
    - Default: msg

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: EmailExport

-Attachment (optional)
    - The attachment parameter specifies whether the attachment should be saved or not. 
    - Default: False

Output
""""""""""""""""""""""""""
The output will be saved to the 'EmailExport' directory within the 'Output' directory.

Permissions
""""""""""""""""""""""""""
- Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application to authenticate with specific scopes that grant the necessary access levels.
- Make sure to connect using the following permission: 'Mail.ReadBasic.All'.
- For instance, if you choose to use User.Read.All, your command would look like this: Connect-MgGraph -Scopes 'Mail.ReadBasic.All'

Get a specific attachment.
^^^^^^^^^^^
Get a specific attachment based on userId and Internet Message Id and saves the output.

Usage
""""""""""""""""""""""""""
Retrieves the attachment from fortunahodan@bonacu.onmicrosoft.com with the internet message identifier <d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com>.
::

   Get-Attachment -userIds fortunahodan@bonacu.onmicrosoft.com -internetMessageId "<d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com>"  

Retrieves an attachment and saves it to C:\Windows\Temp folder.
::

   Get-Attachment -userIds fortunahodan@bonacu.onmicrosoft.com -internetMessageId "<d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com>" -OutputDir C:\Windows\Temp

Parameters
""""""""""""""""""""""""""
-UserIds (Mandatory)
    - The unique identifier of the user.

-InternetMessageId (Mandatory)
    - The InternetMessageId parameter represents the Internet message identifier of an item.

-OutputDir (optional)
    - OutputDir is the parameter specifying the output directory.
    - Default: EmailExport

Output
""""""""""""""""""""""""""
The output will be saved to the 'EmailExport' directory within the 'Output' directory.

Permissions
""""""""""""""""""""""""""
- Before utilizing this function, it is essential to ensure that the appropriate permissions have been granted. This function relies on the Microsoft Graph API and requires an application to authenticate with specific scopes that grant the necessary access levels.
- Make sure to connect using the following permission: 'Mail.ReadBasic.All'.
- For instance, if you choose to use User.Read.All, your command would look like this: Connect-MgGraph -Scopes 'Mail.ReadBasic.All'

Show e-mail.
^^^^^^^^^^^
Show a specific email in the PowerShell Window.

Usage
""""""""""""""""""""""""""
Show a specific email in the PowerShell Window.
::

   Show-Email -userIds {userId} -internetMessageId {InternetMessageId}

Parameters
""""""""""""""""""""""""""
-UserIds (Mandatory)
    - The unique identifier of the user.

-InternetMessageId (Mandatory)
    - The InternetMessageId parameter represents the Internet message identifier of an item.

