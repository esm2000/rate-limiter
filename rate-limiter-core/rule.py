from db import alter_database, get_data_from_database
from util import validate_api_token, validate_category_identifier_combination, validate_rate_limit_unit, validate_requests_per_unit, validate_algorithm
from werkzeug.exceptions import BadRequest, Conflict, Forbidden, Unauthorized

def create_rule(
    auth_header,
    domain,
    category,
    identifier,
    rate_limit_unit,
    requests_per_unit,
    algorithm
):
    if not auth_header or not auth_header.startswith('Bearer '):
        raise Unauthorized("Missing or malformed Authorization header")
    
    if not domain or \
        not category or \
        not identifier or \
        not rate_limit_unit or \
        requests_per_unit is None or \
        not algorithm:
        raise BadRequest(
            ("All information not provided in request. Please include " 
             "domain, category, identifier, rate_limit_unit, requests_per_unit, and alogrithm in request."
            )
        )
    
    # check if service/domain exists
    if not get_data_from_database(f"SELECT id FROM services WHERE id = %s", (domain,)):
        raise BadRequest(f"Service associated with domain {domain} does not exist.")
    
    validate_api_token(auth_header, domain)

    # check if category identifier combination exists
    validate_category_identifier_combination(category, identifier, domain)

    # check input for rate limit unit
    validate_rate_limit_unit(rate_limit_unit)

    # check input for requests_per_unit (must be > 0)
    validate_requests_per_unit(requests_per_unit)

    # check algorithm
    validate_algorithm(algorithm)

    alter_database(
        """
        INSERT INTO rules (domain, category, identifier, rate_limit_unit, requests_present, algorithm)
        VALUES (%s, %s, %s, %s, %s, %s);
        """,
        (
            domain,
            category,
            identifier,
            rate_limit_unit,
            requests_per_unit,
            algorithm
        )
    )