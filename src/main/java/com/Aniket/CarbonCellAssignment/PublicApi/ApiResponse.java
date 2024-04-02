package com.Aniket.CarbonCellAssignment.PublicApi;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ApiResponse {
    private int count;
    private List<DataEntries> entries;
}