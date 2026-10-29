The core of the "AuthCenter" feature of CK-AppIdentity: the party that centralizes the authentication of a local party,
given by the role of the application and the allowed feature (`AuthCenterFeatureDriver`, `ICrisAuthCenter`), the reading of its tokens (`AuthCenterTokenReader`)
and the encryption of the sensitive fields sent to it. An application references the Local or the Remote package.
