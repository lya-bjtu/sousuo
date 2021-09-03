include(P4Build)

set (t "tna_32q_multiprogram")
if (TOFINO)
  p4_build_target(${t}_a ${P4_tofino_ARCHITECTURE} "tofino" "${CMAKE_CURRENT_SOURCE_DIR}/program_a/tna_32q_multiprogram_a.p4")
  p4_build_target(${t}_b ${P4_tofino_ARCHITECTURE} "tofino" "${CMAKE_CURRENT_SOURCE_DIR}/program_b/tna_32q_multiprogram_b.p4")
endif()
if (TOFINO2)
  p4_build_target(${t}_a ${P4_tofino2_ARCHITECTURE} "tofino2" "${CMAKE_CURRENT_SOURCE_DIR}/program_a/tna_32q_multiprogram_a.p4")
  p4_build_target(${t}_b ${P4_tofino2_ARCHITECTURE} "tofino2" "${CMAKE_CURRENT_SOURCE_DIR}/program_b/tna_32q_multiprogram_b.p4")
endif()
if (TOFINO3)
  p4_build_target(${t}_a ${P4_tofino3_ARCHITECTURE} "tofino3" "${CMAKE_CURRENT_SOURCE_DIR}/program_a/tna_32q_multiprogram_a.p4")
  p4_build_target(${t}_b ${P4_tofino3_ARCHITECTURE} "tofino3" "${CMAKE_CURRENT_SOURCE_DIR}/program_b/tna_32q_multiprogram_b.p4")
endif()
add_custom_target(${t} DEPENDS
  $<$<BOOL:${TOFINO}>:${t}_a-tofino>
  $<$<BOOL:${TOFINO}>:${t}_b-tofino>
  $<$<BOOL:${TOFINO2}>:${t}_a-tofino2>
  $<$<BOOL:${TOFINO2}>:${t}_b-tofino2>
  $<$<BOOL:${TOFINO3}>:${t}_a-tofino3>
  $<$<BOOL:${TOFINO3}>:${t}_b-tofino3>
)
