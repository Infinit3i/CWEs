import type { Exercise } from '@/data/exercises'

export const cwe416AsyncCallback: Exercise = {
  cweId: 'CWE-416',
  name: 'Use After Free - Asynchronous Resource Cleanup',
  language: 'Rust',

  vulnerableFunction: `use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

struct Resource {
    data: Vec<u8>,
}

async fn process_async_request(
    request_data: RequestData,
) -> Result<ProcessedData, Box<dyn std::error::Error>> {
    let resource = Arc::new(Resource::new(request_data.size));
    let resource_clone = Arc::clone(&resource);

    // Setup async processing
    setup_resource_data(&resource, &request_data);

    // Start async operation with timeout
    let timeout_task = {
        let resource = Arc::clone(&resource);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            // Implicitly drop resource here
            Err("Request timeout".into())
        })
    };

    let process_task = tokio::spawn(async move {
        match perform_async_operation(request_data).await {
            Ok(result) if result.success => {
                // VULNERABLE: Resource might be dropped by timeout
                process_result_with_resource(&resource_clone, result)
            }
            Ok(_) => Err("Processing failed".into()),
            Err(e) => Err(e.into()),
        }
    });

    tokio::select! {
        result = timeout_task => result.unwrap(),
        result = process_task => result.unwrap(),
    }
}`,

  vulnerableLine: `process_result_with_resource(&resource_clone, result)`,

  options: [
    {
      code: `use std::sync::{Arc, Mutex};

struct ResourceManager {
    resource: Option<Arc<Resource>>,
}

impl ResourceManager {
    fn take_resource(&mut self) -> Option<Arc<Resource>> {
        self.resource.take()
    }
}

async fn process_async_request(
    request_data: RequestData,
) -> Result<ProcessedData, Box<dyn std::error::Error>> {
    let resource_manager = Arc::new(Mutex::new(ResourceManager {
        resource: Some(Arc::new(Resource::new(request_data.size))),
    }));

    let timeout_result = timeout(Duration::from_secs(5), async {
        let result = perform_async_operation(request_data).await?;

        if result.success {
            let resource = resource_manager
                .lock()
                .unwrap()
                .take_resource()
                .ok_or("Resource already consumed")?;

            process_result_with_resource(&resource, result)
        } else {
            Err("Processing failed".into())
        }
    }).await;

    timeout_result?
}`,
      correct: true,
      explanation: `Use Arc and Mutex to manage resource lifecycle safely, ensuring resource is consumed only once`
    },
    {
      code: `const processedData = processResultWithResource(resourceHandle, result);`,
      correct: false,
Use after free causes crashes'
    },
    {
      code: `try { const processedData = processResultWithResource(resourceHandle, result); callback(null, processedData); } catch(e) { callback(e); }`,
      correct: false,
      explanation: 'Try-catch cannot prevent vulnerability'
    },
    {
      code: `if (resourceHandle) { const processedData = processResultWithResource(resourceHandle, result); callback(null, processedData); }`,
      correct: false,
      explanation: 'Truthy check insufficient for freed memory. Deallocated resource handles often retain their reference value while pointing to invalid memory.'
    },
    {
      code: `resourceHandle = allocateResource(requestData.size); const processedData = processResultWithResource(resourceHandle, result);`,
      correct: false,
      explanation: 'Reallocating in callback creates resource leak (original may still exist) and changes the context being processed from the original request setup.'
    },
    {
      code: `clearTimeout(timeoutId); const processedData = processResultWithResource(resourceHandle, result);`,
      correct: false,
      explanation: 'Clearing timeout prevents future deallocation but does not address race condition where timeout already fired and freed the resource before callback execution.'
    },
    {
      code: `if (timeoutId !== null) { const processedData = processResultWithResource(resourceHandle, result); callback(null, processedData); }`,
      correct: false,
      explanation: 'Checking timeout ID does not indicate resource state. Timeout may have fired and freed the resource while timeoutId remains set.'
    },
    {
      code: `const processedData = processResultWithResource(resourceHandle || {}, result);`,
      correct: false,
      explanation: 'Fallback object prevents crashes but provides invalid resource data, leading to incorrect processing results and potentially masking the underlying race condition.'
    },
    {
      code: `setTimeout(() => { const processedData = processResultWithResource(resourceHandle, result); callback(null, processedData); }, 100);`,
      correct: false,
      explanation: 'Additional delay worsens the race condition by increasing the window where timeout deallocation can occur before resource access.'
    },
    {
      code: `if (typeof resourceHandle === "object") { const processedData = processResultWithResource(resourceHandle, result); callback(null, processedData); }`,
      correct: false,
      explanation: 'Type checking does not detect freed memory. Freed resource handles remain object references pointing to invalid/reallocated memory locations.'
    }
  ]
}