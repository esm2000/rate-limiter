from db import alter_database, get_data_from_database
from util import (
    get_rule_from_database,
    validate_algorithm,
    validate_api_token,
    validate_auth_header_present_and_not_malformed,
    validate_category_identifier_combination,
    validate_no_colon,
    validate_rate_limit,
    validate_service_exists
)
from werkzeug.exceptions import BadRequest

def create_rule(
    auth_header,
    domain,
    category,
    identifier,
    window_size,
    rate_limit,
    algorithm
):
    validate_auth_header_present_and_not_malformed(auth_header)
    
    if not domain or \
        not category or \
        not identifier or \
        not window_size or \
        rate_limit is None or \
        not algorithm:
        raise BadRequest(
            ("All information not provided in request. Please include "
             "domain, category, identifier, window_size, rate_limit, and alogrithm in request."
            )
        )

    validate_no_colon(domain, "domain")
    validate_no_colon(category, "category")
    validate_no_colon(identifier, "identifier")

    # check if service/domain exists
    validate_service_exists(domain, True)
    
    validate_api_token(auth_header, domain)

    # check if category identifier combination exists
    validate_category_identifier_combination(category, identifier, domain)

    # check input for algorithm parameters (must be > 0)
    validate_rate_limit(rate_limit)
    validate_rate_limit(window_size)

    # check algorithm
    validate_algorithm(algorithm)

    alter_database(
        """
        INSERT INTO rules (domain, category, identifier, window_size, rate_limit, algorithm)
        VALUES (%s, %s, %s, %s, %s, %s);
        """,
        (
            domain,
            category,
            identifier,
            window_size,
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
    window_size,
    rate_limit,
    algorithm
):
    validate_auth_header_present_and_not_malformed(auth_header)
    
    # check if service/domain exists
    validate_service_exists(domain, True)
    
    validate_api_token(auth_header, domain)

    current_window_size, current_rate_limit, current_algorithm = get_rule_from_database(category, identifier, domain)

    if ((current_window_size == window_size and 
         current_rate_limit == rate_limit and 
         current_algorithm == algorithm) or 
        (window_size is None and rate_limit is None and not algorithm)):
        raise BadRequest("No new fields given for window_size, rate_limit, or algorithm.")
    
    if current_window_size != window_size and window_size is not None:
        # check input for window_size (must be > 0)
        validate_rate_limit(window_size)

    if current_rate_limit != rate_limit and rate_limit is not None:
        # check input for rate_limit (must be > 0)
        validate_rate_limit(rate_limit)
    
    if current_algorithm != algorithm and algorithm:
        # check algorithm
        validate_algorithm(algorithm)
    
    window_size = window_size or current_window_size 
    rate_limit = rate_limit or current_rate_limit
    algorithm = algorithm or current_algorithm

    alter_database(
        """
        UPDATE rules
        SET window_size = %s, rate_limit = %s, algorithm = %s
        WHERE category = %s AND identifier = %s AND domain = %s
        """,
        (
            window_size,
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