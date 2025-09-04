from db import alter_database, get_data_from_database
from util import validate_api_token, validate_category_identifier_combination, validate_rate_limit_unit, validate_rate_limit, validate_algorithm, get_rule_from_database
from werkzeug.exceptions import BadRequest, Unauthorized

def create_rule(
    auth_header,
    domain,
    category,
    identifier,
    rate_limit_unit,
    rate_limit,
    algorithm
):
    if not auth_header or not auth_header.startswith('Bearer '):
        raise Unauthorized("Missing or malformed Authorization header")
    
    if not domain or \
        not category or \
        not identifier or \
        not rate_limit_unit or \
        rate_limit is None or \
        not algorithm:
        raise BadRequest(
            ("All information not provided in request. Please include " 
             "domain, category, identifier, rate_limit_unit, rate_limit, and alogrithm in request."
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
    validate_rate_limit(rate_limit)

    # check algorithm
    validate_algorithm(algorithm)

    alter_database(
        """
        INSERT INTO rules (domain, category, identifier, rate_limit_unit, rate_limit, algorithm)
        VALUES (%s, %s, %s, %s, %s, %s);
        """,
        (
            domain,
            category,
            identifier,
            rate_limit_unit,
            rate_limit,
            algorithm
        )
    )

def get_rule_info(auth_header, domain, category, identifier):
    if not auth_header or not auth_header.startswith('Bearer '):
        raise Unauthorized("Missing or malformed Authorization header")
    
    # check if service/domain exists
    if not get_data_from_database(f"SELECT id FROM services WHERE id = %s", (domain,)):
        raise BadRequest(f"Service associated with domain {domain} does not exist.")
    
    validate_api_token(auth_header, domain)

    return get_rule_from_database(category, identifier, domain)

def update_rule(
    auth_header,
    domain,
    category,
    identifier,
    rate_limit_unit,
    rate_limit,
    algorithm
):
    if not auth_header or not auth_header.startswith('Bearer '):
        raise Unauthorized("Missing or malformed Authorization header")
    
    # check if service/domain exists
    if not get_data_from_database(f"SELECT id FROM services WHERE id = %s", (domain,)):
        raise BadRequest(f"Service associated with domain {domain} does not exist.")
    
    validate_api_token(auth_header, domain)

    current_rate_limit_unit, current_rate_limit, current_algorithm = get_rule_from_database(category, identifier, domain)

    if ((current_rate_limit_unit == rate_limit_unit and 
         current_rate_limit == rate_limit and 
         current_algorithm == algorithm) or 
        (not rate_limit_unit and rate_limit is None and not algorithm)):
        raise BadRequest("No new fields given for rate_limit_unit, rate_limit, or algorithm.")
    
    if current_rate_limit_unit != rate_limit_unit and rate_limit_unit:
        # check input for rate limit unit
        validate_rate_limit_unit(rate_limit_unit)

    if current_rate_limit != rate_limit and rate_limit is not None:
        # check input for requests_per_unit (must be > 0)
        validate_rate_limit(rate_limit)
    
    if current_algorithm != algorithm and algorithm:
        # check algorithm
        validate_algorithm(algorithm)
    
    rate_limit_unit = rate_limit_unit or current_rate_limit_unit
    rate_limit = rate_limit or current_rate_limit
    algorithm = algorithm or current_algorithm

    alter_database(
        """
        UPDATE rules
        SET rate_limit_unit = %s, rate_limit = %s, algorithm = %s
        WHERE category = %s AND identifier = %s AND domain = %s
        """,
        (
            rate_limit_unit,
            rate_limit,
            algorithm,
            category,
            identifier,
            domain
        )
    )

def delete_rule(
    auth_header,
    domain,
    category,
    identifier
):
    if not auth_header or not auth_header.startswith('Bearer '):
        raise Unauthorized("Missing or malformed Authorization header")
    
    # check if service/domain exists
    if not get_data_from_database(f"SELECT id FROM services WHERE id = %s", (domain,)):
        raise BadRequest(f"Service associated with domain {domain} does not exist.")
    
    validate_api_token(auth_header, domain)

    # fails with BadRequest if rule does not exist
    get_rule_from_database(category, identifier, domain)
    
    alter_database(
        """
        DELETE FROM rules WHERE category = %s AND identifier = %s AND domain = %s
        """,
        (category, identifier, domain)
    )