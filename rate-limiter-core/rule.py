from db import alter_database, get_data_from_database
from util import (
    get_rule_from_database,
    validate_algorithm, 
    validate_api_token,
    validate_auth_header_present_and_not_malformed,
    validate_category_identifier_combination,
    validate_rate_limit_unit,
    validate_rate_limit,
    validate_service_exists
)
from werkzeug.exceptions import BadRequest

def create_rule(
    auth_header,
    domain,
    category,
    identifier,
    rate_limit_unit,
    rate_limit,
    algorithm
):
    validate_auth_header_present_and_not_malformed(auth_header)
    
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
    validate_service_exists(domain, True)
    
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
    validate_auth_header_present_and_not_malformed(auth_header)
    
    # check if service/domain exists
    validate_service_exists(domain, True)
    
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
    validate_auth_header_present_and_not_malformed(auth_header)
    
    # check if service/domain exists
    validate_service_exists(domain, True)
    
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
    validate_auth_header_present_and_not_malformed(auth_header)
    
    # check if service/domain exists
    validate_service_exists(domain, True)
    
    validate_api_token(auth_header, domain)

    # fails with BadRequest if rule does not exist
    get_rule_from_database(category, identifier, domain)
    
    alter_database(
        """
        DELETE FROM rules WHERE category = %s AND identifier = %s AND domain = %s
        """,
        (category, identifier, domain)
    )