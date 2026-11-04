The core of the "AuthCenter" feature of CK-AppIdentity: the party that centralizes the authentication of a local party,
given by the configuration of each local party (`AuthCenterFeature`, `ICrisAuthCenter`), the reading of its tokens (`AuthCenterTokenReader`)
and the encryption of the sensitive fields sent to it. The Local and the Remote packages implement the two sides of this asymmetric feature.
