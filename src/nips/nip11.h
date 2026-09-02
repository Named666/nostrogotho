#ifndef NIP11_H_
#define NIP11_H_

/*
 * NIP-11 Relay Information Document
 *
 * Returns the static information document advertised by this relay. Transport
 * code owns HTTP negotiation and uses this payload only after Accept matching.
 */
const char *nip11_information_document(void);

#endif /* NIP11_H_ */