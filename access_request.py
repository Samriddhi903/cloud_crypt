import uuid
from datetime import datetime
import json
import os
from typing import List, Dict, Tuple, Any, Optional

class AccessRequest:
    def __init__(self, request_id: str, filename: str, requestor: str, 
                 approver: str, status: str = "pending", 
                 created_at: str = None, updated_at: str = None):
        self.request_id = request_id
        self.filename = filename
        self.requestor = requestor
        self.approver = approver
        self.status = status
        self.created_at = created_at or datetime.now().isoformat()
        self.updated_at = updated_at or self.created_at
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "filename": self.filename,
            "requestor": self.requestor,
            "approver": self.approver,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AccessRequest':
        return cls(
            request_id=data["request_id"],
            filename=data["filename"],
            requestor=data["requestor"],
            approver=data["approver"],
            status=data["status"],
            created_at=data["created_at"],
            updated_at=data["updated_at"]
        )

class AccessRequestManager:
    def __init__(self, storage_path: str = "storage/access_requests.json"):
        self.storage_path = storage_path
        self.requests: Dict[str, AccessRequest] = {}
        self.load_requests()
    
    def load_requests(self) -> None:
        """Load access requests from storage"""
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r') as f:
                    data = json.load(f)
                    for req_id, req_data in data.items():
                        self.requests[req_id] = AccessRequest.from_dict(req_data)
                print(f"Loaded {len(self.requests)} access requests from storage")
            except Exception as e:
                print(f"Error loading access requests: {e}")
        else:
            print("No access requests file found, starting with empty requests")
    
    def save_requests(self) -> bool:
        """Save access requests to storage"""
        try:
            requests_dict = {
                req_id: req.to_dict() for req_id, req in self.requests.items()
            }
            with open(self.storage_path, 'w') as f:
                json.dump(requests_dict, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving access requests: {e}")
            return False
    
    def create_request(self, filename: str, requestor: str, approver: str) -> Tuple[bool, str]:
        """Create a new access request"""
        try:
            # Check if a similar request already exists
            for req in self.requests.values():
                if (req.filename == filename and 
                    req.requestor == requestor and 
                    req.status == "pending"):
                    return False, f"A pending request for this file already exists"
            
            # Create new request
            request_id = str(uuid.uuid4())
            request = AccessRequest(
                request_id=request_id,
                filename=filename,
                requestor=requestor,
                approver=approver
            )
            
            self.requests[request_id] = request
            self.save_requests()
            
            return True, request_id
        except Exception as e:
            return False, str(e)
    
    def update_request_status(self, request_id: str, new_status: str) -> Tuple[bool, str]:
        """Update the status of an access request"""
        if request_id not in self.requests:
            return False, "Request not found"
        
        if new_status not in ["approved", "rejected"]:
            return False, f"Invalid status: {new_status}"
        
        try:
            request = self.requests[request_id]
            request.status = new_status
            request.updated_at = datetime.now().isoformat()
            
            self.save_requests()
            return True, f"Request {new_status} successfully"
        except Exception as e:
            return False, str(e)
    
    def get_requests_from_requestor(self, requestor: str) -> List[AccessRequest]:
        """Get all requests made by a specific requestor"""
        return [req for req in self.requests.values() if req.requestor == requestor]
    
    def get_requests_for_approver(self, approver: str) -> List[AccessRequest]:
        """Get all pending requests for a specific approver"""
        return [req for req in self.requests.values() 
                if req.approver == approver and req.status == "pending"]
    
    def get_request_by_id(self, request_id: str) -> Optional[AccessRequest]:
        """Get a specific request by ID"""
        return self.requests.get(request_id)
    
    def get_pending_request_count(self, approver: str) -> int:
        """Get count of pending requests for an approver"""
        return len(self.get_requests_for_approver(approver))