 # AMSI.fail 
C# Azure Function with an HTTP trigger that generates obfuscated PowerShell snippets that break or disable AMSI for the current process.
The snippets are randomly selected from a small pool of techniques/variations before being obfuscated.Every snippet is obfuscated at runtime/request so that no generated output share the same signatures.
