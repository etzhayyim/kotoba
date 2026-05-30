#[cfg(test)]
mod router_tests {
    use axum::http::Request;
    use axum::body::Body;
    use tower::ServiceExt;
    use super::*;

    #[tokio::test]
    async fn test_generic_xrpc_route() {
        let state = Arc::new(crate::server::KotobaState::new(None).expect("state"));
        let app = crate::build_router(state);
        
        let req = Request::builder()
            .method("POST")
            .uri("/xrpc/ai.gftd.apps.yata.my_method")
            .body(Body::empty())
            .unwrap();
            
        let response = app.oneshot(req).await.unwrap();
        
        // As long as it's not 404 Not Found, it hit the router
        assert_ne!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }
}
