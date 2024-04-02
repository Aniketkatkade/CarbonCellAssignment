package com.Aniket.CarbonCellAssignment.PublicApi;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Data
@NoArgsConstructor
@AllArgsConstructor
@RequestMapping("/dataRetrieval")
public class DataRetrievalController {

    @Autowired
    DataRetrievalService dataRetrievalService;

    @GetMapping("/publicApi/categories")
    public ResponseEntity<?> getApiEntries(
            @RequestParam(required = false) String category,
            @RequestParam(required = false) Integer limit) {
        return dataRetrievalService.getApiEntries(category, limit);
    }


}
