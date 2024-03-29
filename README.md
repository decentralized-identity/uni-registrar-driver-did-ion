![DIF Logo](https://raw.githubusercontent.com/decentralized-identity/universal-registrar/master/docs/logo-dif.png)

# Universal Registrar Driver: ion

This is a [Universal Registrar](https://github.com/decentralized-identity/universal-registrar/) driver for **did:ion** identifiers.

## Specifications

* [Decentralized Identifiers](https://w3c.github.io/did-core/)
* [DID Method Specification](https://github.com/decentralized-identity/ion)

## Build and Run (Docker)

```
docker build -f ./docker/Dockerfile . -t universalregistrar/driver-did-ion
docker run -p 9080:9080 universalregistrar/driver-did-ion
```

## Driver Environment Variables


```
uniregistrar_driver_did_ion_api=<API Endpoint of a ION Node including the operations path>
```

