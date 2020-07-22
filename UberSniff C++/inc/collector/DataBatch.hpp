#pragma once

#include <string>
#include <list>
#include <unordered_map>

namespace ubersniff::collector {
    /*
    * Represent a batch of data
    */
    struct DataBatch {
        // Batch of images: key is the uri of the image and the value is the number of time it appears
        std::unordered_map<std::string, int> images;
        // Batch of images: key is the text itself and the value is the number of time it appears
        std::unordered_map<std::string, int> texts;
    };

    /*
    * Represent the map of batches to send to UberBack
    * The Key is the URL source of the batch
    * The Value is the batch itself
    */
    using DataBatches = std::unordered_map<std::string, DataBatch>;
}
