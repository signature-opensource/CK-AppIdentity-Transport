The core of the "AuthCenter" feature of CK-AppIdentity: the party that centralizes the authentication of a local party
(the root application identity or a tenant domain).

It provides the designation of the Authentication Center in the configuration of each local party (`AuthCenterFeature`,
`ICrisAuthCenter`), the reading of its tokens (`AuthCenterTokenReader`) and the encryption of the sensitive fields sent
to it. An application references CK.AppIdentity.AuthCenter.Local (it is the AuthCenter) or
CK.AppIdentity.AuthCenter.Remote (it is a remote of an AuthCenter): they implement the two sides of this asymmetric feature.
