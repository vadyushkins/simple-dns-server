import copy
import socket

import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

ROOT_SERVERS = [
    "198.41.0.4",
    "199.9.14.201",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33",
]

cache = dict()

client_socket = dns.query._make_socket(
    af=socket.AF_INET,
    type=socket.SOCK_DGRAM,
    source=("localhost", 53),
)


def resolve(query):
    if query in cache:
        return cache[query]

    query_message = dns.message.make_query(
        qname=query,
        rdtype=dns.rdatatype.A,
        rdclass=dns.rdataclass.IN,
    )

    for root_server in ROOT_SERVERS:
        response = resolve_recursive(query_message, root_server)

        if response is not None:
            cache[query] = response
            return response

    return None


def resolve_recursive(query, where):
    response = dns.query.udp(
        q=query,
        where=where,
        raise_on_truncation=False,
    )

    if response:
        if response.answer:
            return response
        elif response.additional:
            for additional in response.additional:
                if additional.rdtype != dns.rdatatype.A:
                    continue
                for add in additional:
                    new_response = resolve_recursive(query, str(add))
                    if new_response:
                        return new_response

    return response


if __name__ == "__main__":
    while True:
        request, _, from_address = dns.query.receive_udp(client_socket)

        query = str(request.question[0]).split()[0]

        response = copy.deepcopy(request)

        result = resolve(dns.name.from_text(query))

        if result is not None:
            response.answer = resolve(dns.name.from_text(query)).answer
            response.flags |= dns.flags.QR | dns.flags.RA
            if response.flags & dns.flags.AD:
                response.flags ^= dns.flags.AD

        dns.query.send_udp(client_socket, response, from_address)
