#!/usr/bin/env python3
"""
Tests for platform data utilities.

Tests for the unified platform-specific data handling functions.
"""

import pytest
from website_security_scanner.utils.platform_data import (
    get_platform_findings,
    get_platform_identifiers,
    get_api_patterns,
    set_platform_findings,
    normalize_platform_name,
    get_supported_platforms,
    extract_platform_from_results,
    PLATFORM_FIELD_MAPPINGS
)


class TestGetPlatformFindings:
    """Test cases for get_platform_findings function."""

    def test_get_bubble_findings_primary_key(self):
        """Test getting bubble findings using primary key."""
        results = {
            'bubble_specific': {'test': 'data'},
            'url': 'https://example.com'
        }
        findings = get_platform_findings('bubble', results)
        assert findings == {'test': 'data'}

    def test_get_bubble_findings_alternative_keys(self):
        """Test getting bubble findings using alternative keys."""
        results = {
            'bubble_specific_findings': {'test': 'data'},
            'url': 'https://example.com'
        }
        findings = get_platform_findings('bubble', results)
        assert findings == {'test': 'data'}

        results = {
            'bubble_findings': {'test': 'data2'},
            'url': 'https://example.com'
        }
        findings = get_platform_findings('bubble', results)
        assert findings == {'test': 'data2'}

    def test_get_outsystems_findings(self):
        """Test getting outsystems findings."""
        results = {
            'outsystems_specific': {'test': 'outsystems'}
        }
        findings = get_platform_findings('outsystems', results)
        assert findings == {'test': 'outsystems'}

    def test_get_airtable_findings(self):
        """Test getting airtable findings."""
        results = {
            'airtable_specific': {'test': 'airtable'}
        }
        findings = get_platform_findings('airtable', results)
        assert findings == {'test': 'airtable'}

    def test_get_shopify_findings(self):
        """Test getting shopify findings."""
        results = {
            'shopify_specific': {'test': 'shopify'}
        }
        findings = get_platform_findings('shopify', results)
        assert findings == {'test': 'shopify'}

    def test_get_webflow_findings(self):
        """Test getting webflow findings."""
        results = {
            'webflow_specific': {'test': 'webflow'}
        }
        findings = get_platform_findings('webflow', results)
        assert findings == {'test': 'webflow'}

    def test_get_wix_findings(self):
        """Test getting wix findings."""
        results = {
            'wix_specific': {'test': 'wix'}
        }
        findings = get_platform_findings('wix', results)
        assert findings == {'test': 'wix'}

    def test_get_mendix_findings(self):
        """Test getting mendix findings."""
        results = {
            'mendix_specific': {'test': 'mendix'}
        }
        findings = get_platform_findings('mendix', results)
        assert findings == {'test': 'mendix'}

    def test_get_generic_findings(self):
        """Test getting generic findings."""
        results = {
            'generic_analysis': {'test': 'generic'}
        }
        findings = get_platform_findings('generic', results)
        assert findings == {'test': 'generic'}

    def test_no_findings_found(self):
        """Test when no findings are found."""
        results = {'url': 'https://example.com'}
        findings = get_platform_findings('bubble', results)
        assert findings == {}

    def test_no_findings_without_fallback(self):
        """Test when no findings are found and fallback is disabled."""
        results = {'url': 'https://example.com'}
        findings = get_platform_findings('bubble', results, default_fallback=False)
        assert findings is None

    def test_unknown_platform(self):
        """Test with unknown platform name."""
        results = {'custom_specific': {'test': 'data'}}
        findings = get_platform_findings('custom', results)
        # Unknown platforms fall back to direct lookup
        assert findings == {'test': 'data'}

    def test_case_insensitive(self):
        """Test that platform name is case-insensitive."""
        results = {
            'bubble_specific': {'test': 'data'}
        }
        findings = get_platform_findings('BUBBLE', results)
        assert findings == {'test': 'data'}

        findings = get_platform_findings('Bubble', results)
        assert findings == {'test': 'data'}

    def test_whitespace_handling(self):
        """Test whitespace handling in platform name."""
        results = {
            'bubble_specific': {'test': 'data'}
        }
        findings = get_platform_findings('  bubble  ', results)
        assert findings == {'test': 'data'}

    def test_none_inputs(self):
        """Test handling of None inputs."""
        assert get_platform_findings(None, {}) == {}
        assert get_platform_findings('bubble', None) == {}


class TestGetPlatformIdentifiers:
    """Test cases for get_platform_identifiers function."""

    def test_get_bubble_identifiers(self):
        """Test getting bubble identifier patterns."""
        identifiers = get_platform_identifiers('bubble')
        assert '_bubble' in identifiers
        assert 'bubble_f_' in identifiers
        assert 'bubble_' in identifiers

    def test_get_outsystems_identifiers(self):
        """Test getting outsystems identifier patterns."""
        identifiers = get_platform_identifiers('outsystems')
        assert 'outsystems' in identifiers
        assert 'os_' in identifiers
        assert 'screen_' in identifiers

    def test_get_airtable_identifiers(self):
        """Test getting airtable identifier patterns."""
        identifiers = get_platform_identifiers('airtable')
        assert 'airtable' in identifiers
        assert 'rec_' in identifiers
        assert 'tbl_' in identifiers
        assert 'view_' in identifiers

    def test_get_shopify_identifiers(self):
        """Test getting shopify identifier patterns."""
        identifiers = get_platform_identifiers('shopify')
        assert 'shopify' in identifiers
        assert 'shopify_' in identifiers
        assert 'cdn.shopify.com' in identifiers

    def test_get_webflow_identifiers(self):
        """Test getting webflow identifier patterns."""
        identifiers = get_platform_identifiers('webflow')
        assert 'webflow' in identifiers
        assert 'w-' in identifiers
        assert 'data-wf-' in identifiers

    def test_get_wix_identifiers(self):
        """Test getting wix identifier patterns."""
        identifiers = get_platform_identifiers('wix')
        assert 'wix' in identifiers
        assert 'wix-' in identifiers
        assert 'wix_' in identifiers

    def test_get_mendix_identifiers(self):
        """Test getting mendix identifier patterns."""
        identifiers = get_platform_identifiers('mendix')
        assert 'mendix' in identifiers
        assert 'mx_' in identifiers
        assert 'mxdata_' in identifiers

    def test_get_generic_identifiers(self):
        """Test getting generic identifier patterns."""
        identifiers = get_platform_identifiers('generic')
        assert identifiers == []

    def test_unknown_platform_identifiers(self):
        """Test getting identifiers for unknown platform."""
        identifiers = get_platform_identifiers('unknown')
        assert identifiers == []

    def test_case_insensitive(self):
        """Test that platform name is case-insensitive."""
        assert get_platform_identifiers('BUBBLE') == get_platform_identifiers('bubble')
        assert get_platform_identifiers('Bubble') == get_platform_identifiers('bubble')


class TestGetApiPatterns:
    """Test cases for get_api_patterns function."""

    def test_get_bubble_api_patterns(self):
        """Test getting bubble API patterns."""
        patterns = get_api_patterns('bubble')
        assert 'api.bubble.io' in patterns
        assert 'bubble.io/api' in patterns

    def test_get_outsystems_api_patterns(self):
        """Test getting outsystems API patterns."""
        patterns = get_api_patterns('outsystems')
        assert 'outsystems.com' in patterns
        assert 'outsystemscloud.com' in patterns

    def test_get_airtable_api_patterns(self):
        """Test getting airtable API patterns."""
        patterns = get_api_patterns('airtable')
        assert 'api.airtable.com' in patterns
        assert 'airtable.com/api' in patterns

    def test_get_shopify_api_patterns(self):
        """Test getting shopify API patterns."""
        patterns = get_api_patterns('shopify')
        assert 'shopify.com' in patterns
        assert 'myshopify.com' in patterns

    def test_get_webflow_api_patterns(self):
        """Test getting webflow API patterns."""
        patterns = get_api_patterns('webflow')
        assert 'webflow.com' in patterns
        assert 'webflow.io' in patterns

    def test_get_wix_api_patterns(self):
        """Test getting wix API patterns."""
        patterns = get_api_patterns('wix')
        assert 'wix.com' in patterns
        assert 'wix-code.com' in patterns

    def test_get_mendix_api_patterns(self):
        """Test getting mendix API patterns."""
        patterns = get_api_patterns('mendix')
        assert 'mendix.com' in patterns
        assert 'mendixcloud.com' in patterns

    def test_get_generic_api_patterns(self):
        """Test getting generic API patterns."""
        patterns = get_api_patterns('generic')
        assert patterns == []

    def test_unknown_platform_api_patterns(self):
        """Test getting API patterns for unknown platform."""
        patterns = get_api_patterns('unknown')
        assert patterns == []


class TestSetPlatformFindings:
    """Test cases for set_platform_findings function."""

    def test_set_bubble_findings(self):
        """Test setting bubble findings."""
        results = {'url': 'https://example.com'}
        findings = {'test': 'data'}
        updated = set_platform_findings('bubble', results, findings)
        assert updated['bubble_specific'] == {'test': 'data'}

    def test_set_outsystems_findings(self):
        """Test setting outsystems findings."""
        results = {'url': 'https://example.com'}
        findings = {'test': 'outsystems'}
        updated = set_platform_findings('outsystems', results, findings)
        assert updated['outsystems_specific'] == {'test': 'outsystems'}

    def test_set_generic_findings(self):
        """Test setting generic findings."""
        results = {'url': 'https://example.com'}
        findings = {'test': 'generic'}
        updated = set_platform_findings('generic', results, findings)
        assert updated['generic_specific'] == {'test': 'generic'}

    def test_set_unknown_platform_findings(self):
        """Test setting findings for unknown platform."""
        results = {'url': 'https://example.com'}
        findings = {'test': 'data'}
        updated = set_platform_findings('custom', results, findings)
        assert updated['custom_specific'] == {'test': 'data'}

    def test_set_findings_overwrites(self):
        """Test that setting findings overwrites existing data."""
        results = {
            'bubble_specific': {'old': 'data'},
            'url': 'https://example.com'
        }
        findings = {'new': 'data'}
        updated = set_platform_findings('bubble', results, findings)
        assert updated['bubble_specific'] == {'new': 'data'}
        assert 'old' not in updated['bubble_specific']

    def test_none_inputs(self):
        """Test handling of None inputs."""
        results = {'url': 'https://example.com'}
        updated = set_platform_findings(None, results, {})
        assert updated == results

        updated = set_platform_findings('bubble', None, {})
        assert updated is None


class TestNormalizePlatformName:
    """Test cases for normalize_platform_name function."""

    def test_normalize_standard_platforms(self):
        """Test normalization of standard platform names."""
        assert normalize_platform_name('bubble') == 'bubble'
        assert normalize_platform_name('outsystems') == 'outsystems'
        assert normalize_platform_name('airtable') == 'airtable'
        assert normalize_platform_name('shopify') == 'shopify'
        assert normalize_platform_name('webflow') == 'webflow'
        assert normalize_platform_name('wix') == 'wix'
        assert normalize_platform_name('mendix') == 'mendix'
        assert normalize_platform_name('generic') == 'generic'

    def test_normalize_case_insensitive(self):
        """Test that normalization is case-insensitive."""
        assert normalize_platform_name('BUBBLE') == 'bubble'
        assert normalize_platform_name('Bubble') == 'bubble'
        assert normalize_platform_name('BUBBLE') == 'bubble'

    def test_normalize_platform_variations(self):
        """Test normalization of platform name variations."""
        assert normalize_platform_name('web') == 'generic'
        assert normalize_platform_name('unknown') == 'generic'

    def test_normalize_whitespace_handling(self):
        """Test whitespace handling in normalization."""
        assert normalize_platform_name('  bubble  ') == 'bubble'
        assert normalize_platform_name('\tbubble\t') == 'bubble'

    def test_normalize_none_input(self):
        """Test normalization of None input."""
        assert normalize_platform_name(None) == 'generic'

    def test_normalize_empty_input(self):
        """Test normalization of empty input."""
        # Empty strings return 'generic'
        assert normalize_platform_name('') == 'generic'
        # Whitespace-only strings become empty after strip, then return '' (not in mapping)
        assert normalize_platform_name('  ') == ''


class TestGetSupportedPlatforms:
    """Test cases for get_supported_platforms function."""

    def test_get_all_supported_platforms(self):
        """Test getting all supported platforms."""
        platforms = get_supported_platforms()
        assert 'bubble' in platforms
        assert 'outsystems' in platforms
        assert 'airtable' in platforms
        assert 'shopify' in platforms
        assert 'webflow' in platforms
        assert 'wix' in platforms
        assert 'mendix' in platforms
        assert 'generic' in platforms

    def test_platforms_count(self):
        """Test that all 8 platforms are supported."""
        platforms = get_supported_platforms()
        assert len(platforms) == 8


class TestExtractPlatformFromResults:
    """Test cases for extract_platform_from_results function."""

    def test_extract_from_platform_type(self):
        """Test extracting platform from platform_type field."""
        results = {'platform_type': 'bubble'}
        assert extract_platform_from_results(results) == 'bubble'

    def test_extract_from_platform_field(self):
        """Test extracting platform from platform field."""
        results = {'platform': 'outsystems'}
        assert extract_platform_from_results(results) == 'outsystems'

    def test_extract_platform_field_takes_precedence(self):
        """Test that platform_type takes precedence."""
        results = {'platform_type': 'bubble', 'platform': 'outsystems'}
        assert extract_platform_from_results(results) == 'bubble'

    def test_extract_from_findings_bubble(self):
        """Test inferring platform from bubble findings."""
        results = {'bubble_specific': {'test': 'data'}}
        assert extract_platform_from_results(results) == 'bubble'

    def test_extract_from_findings_outsystems(self):
        """Test inferring platform from outsystems findings."""
        results = {'outsystems_specific': {'test': 'data'}}
        assert extract_platform_from_results(results) == 'outsystems'

    def test_extract_from_findings_generic(self):
        """Test inferring generic platform."""
        results = {'generic_analysis': {'test': 'data'}}
        assert extract_platform_from_results(results) == 'generic'

    def test_extract_default_to_generic(self):
        """Test defaulting to generic when no platform found."""
        results = {'url': 'https://example.com'}
        assert extract_platform_from_results(results) == 'generic'

    def test_extract_case_insensitive(self):
        """Test that extraction normalizes platform name."""
        results = {'platform_type': 'BUBBLE'}
        assert extract_platform_from_results(results) == 'bubble'

    def test_extract_with_variations(self):
        """Test extraction with platform name variations."""
        results = {'platform_type': 'web'}
        assert extract_platform_from_results(results) == 'generic'


class TestPlatformFieldMappings:
    """Test PLATFORM_FIELD_MAPPINGS constant."""

    def test_all_platforms_have_mappings(self):
        """Test that all platforms have field mappings."""
        platforms = ['bubble', 'outsystems', 'airtable', 'shopify', 'webflow', 'wix', 'mendix', 'generic']
        for platform in platforms:
            assert platform in PLATFORM_FIELD_MAPPINGS

    def test_mapping_structure(self):
        """Test that each mapping has required keys."""
        required_keys = ['findings_key', 'alternative_keys', 'api_patterns', 'identifier_patterns']
        for platform, mapping in PLATFORM_FIELD_MAPPINGS.items():
            for key in required_keys:
                assert key in mapping

    def test_bubble_mapping(self):
        """Test bubble mapping values."""
        mapping = PLATFORM_FIELD_MAPPINGS['bubble']
        assert mapping['findings_key'] == 'bubble_specific'
        assert 'bubble_specific_findings' in mapping['alternative_keys']
        assert 'api.bubble.io' in mapping['api_patterns']
        assert '_bubble' in mapping['identifier_patterns']

    def test_outsystems_mapping(self):
        """Test outsystems mapping values."""
        mapping = PLATFORM_FIELD_MAPPINGS['outsystems']
        assert mapping['findings_key'] == 'outsystems_specific'
        assert 'outsystems.com' in mapping['api_patterns']
        assert 'outsystems' in mapping['identifier_patterns']

    def test_generic_mapping(self):
        """Test generic mapping values."""
        mapping = PLATFORM_FIELD_MAPPINGS['generic']
        assert mapping['findings_key'] == 'generic_specific'
        assert mapping['api_patterns'] == []
        assert mapping['identifier_patterns'] == []
