/**
 * @file metadata_sys.h
 * @brief Sys-context (Global system fields) metadata handler
 */


#ifndef SRC_COMMON_METADATA_HANDLERS_METADATA_SYS_H_
#define SRC_COMMON_METADATA_HANDLERS_METADATA_SYS_H_

#include "metadata_generic.h"
#include "auto_gen/global_sys_fields_lookup.h"
#include "auto_gen/tdr_tdcs_fields_lookup.h"
#include "auto_gen/td_vmcs_fields_lookup.h"
#include "auto_gen/tdvps_fields_lookup.h"
#include "helpers/error_reporting.h"

api_error_code_e md_sys_read_element(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
        md_access_qualifier_t access_qual, uint64_t* out_rd_value);

api_error_code_e md_sys_read_field(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
        md_access_qualifier_t access_qual, uint64_t value[MAX_ELEMENTS_IN_FIELD]);

api_error_code_e md_sys_write_element(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
        md_access_qualifier_t access_qual, uint64_t wr_value, uint64_t wr_request_mask,
        uint64_t* old_value);

api_error_code_e md_sys_write_field(md_field_id_t field_id, const md_lookup_t* entry, md_access_t access_type,
        md_access_qualifier_t access_qual, uint64_t value[MAX_ELEMENTS_IN_FIELD], uint64_t wr_mask);

#endif /* SRC_COMMON_METADATA_HANDLERS_METADATA_SYS_H_ */
