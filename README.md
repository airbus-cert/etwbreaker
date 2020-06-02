# etwbreaker
An IDA Plugin to statically find ETW events in a PE file and generate a Conditional Breakpoint to facilitate Security Research.

![Demo](img/demo.gif)

## How To Install?

Just put the `etwbreaker.py` script in the `plugins` folder of IDA.

```
git clone git@github.com:Airbus-CERT/etwbreaker.git
mklink "C:\\Program Files\\IDA Pro 7.4\\plugins\\etwbreaker.py" "etwbreaker\etwbreaker.py"
```

Launch your IDA and press `Ctrl-Shift-L` to activate it.

## How Does It Work?

`ETWBreaker` try to find all references about ETW providers statically compiled into a Windows module.

### Manifest-based Provider

`ETWBreaker` will try to find a resource name `WEVT_TEMPLATE`. This resource includes the ETW manifest for the module.
Once we get all events available, we can compute a signature and try to find the associated symbol of the event to enrich analysis.
Then we can also generate a conditional breakpoint to debug the module only once the target event is triggered.

### Tracelogging provider

`Microsoft` recently added the `Tracelogging` API, that works over ETW but without manifests.
Tracelogging encompasses its scheme directly into a special ETW field named `ExtendedData`.
The Tracelogging API is a macro-based API, it means that schemes are generated at compilation and can be retrieved statically.
Scheme data are contained in a bordered region for security purposes, and can be retrieved easily.

But, to the contrary of manifest-based ETW, the link between event and provider is made at execution time, and all events have the same ID (0).
This is why we list only providers in case of Tracelogging.

## SSTIC (Symposium sur la sécurité des technologies de l'information et des communications)

This project is part of presentation made for [SSTIC](https://www.sstic.org/2020/presentation/quand_les_bleus_se_prennent_pour_des_chercheurs_de_vulnrabilites/)
