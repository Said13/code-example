import Foundation
import Alamofire
import Crashlytics

struct ModalRequest {
    var method: HTTPMethod
    var path: String
    var parameters: Parameters?
    var encoding: ParameterEncoding
    var headers: HTTPHeaders?
    
    init() {
        method = .get
        path = ""
        parameters = nil
        encoding = JSONEncoding() as ParameterEncoding
        headers = ["Content-Type": "application/json",
                   "X-Requested-With": "XMLHttpRequest",
                   "Cache-Control": "no-cache"]
    }
}

//swiftlint:disable cyclomatic_complexity function_body_length line_length
class APIRouter {
    
    lazy var defaultsManager: DefaultsManager = AppContext.shared.defaults
    let authAPI: AuthAPI = .init()
    var lastRequest: ModalRequest?
    var mainUrl: URL = Environment.rootURL
    static var nowIsRefreshing: Bool = false
    let decoder: DataDecoder = JSONDecoder()
    private var savedRequests: [DispatchWorkItem] = []
    
    var isTokenExpiring: Bool {
        guard let tokenExpireDate = defaultsManager.tokenExpireDate,
            let minutesToExpire = Calendar.current.dateComponents([.minute], from: Date(), to: tokenExpireDate).minute else { return false }
        return minutesToExpire < 1
    }
    
    func send<T: Decodable>(url: String,
                            method: HTTPMethod = .get,
                            parameters: Parameters? = nil,
                            encoding: ParameterEncoding = JSONEncoding.default,
                            additionalQueryParams: Parameters? = nil,
                            headers: HTTPHeaders? = nil,
                            completion: @escaping (AFDataResponse<T>) -> Void) -> DataRequest? {
        var currentRequest: DataRequest?
        if APIRouter.nowIsRefreshing, isBlackListRequest(url: url) {
            saveRequest {
                currentRequest = self.makeRequest(url: url, method: method, parameters: parameters, encoding: encoding, additionalQueryParams: additionalQueryParams, headers: headers) { (response) in
                    completion(response)
                }
            }
        }
        
        if (isTokenExpiring || defaultsManager.accessToken == nil) && isBlackListRequest(url: url) {
            APIRouter.nowIsRefreshing = true
            
            saveRequest { [weak self] in
                guard let self = self else { return }
                currentRequest = self.makeRequest(url: url, method: method, parameters: parameters, encoding: encoding, additionalQueryParams: additionalQueryParams, headers: headers) { (response) in
                    completion(response)
                }
            }
            
            self.refreshToken { [weak self] _ in
                guard let self = self else { return }
                APIRouter.nowIsRefreshing = false
                self.executeAllSavedRequests()
            }
        } else {
            currentRequest = self.makeRequest(url: url, method: method, parameters: parameters, encoding: encoding, additionalQueryParams: additionalQueryParams, headers: headers) { (response) in
                completion(response)
            }
        }
        
        return currentRequest
    }
    
    func refreshToken(result: @escaping (AFDataResponse<Token>) -> Void) {
        guard let refreshToken = self.defaultsManager.refreshToken
            else {
                self.logOut()
                return
        }

        let parametersForLogin: Parameters = [
            Constant.AppKeys.refreshToken: refreshToken
        ]
        
        let headersForLogin: HTTPHeaders = [
            Constant.HTTPHeaderField.contentType: "application/json",
            Constant.HTTPHeaderField.acceptType: "application/json"
        ]

        cleanCache()
        
        let addParamsForRefresh: Parameters = [
            Constant.AppKeys.clientID: Constant.AppKeys.mobileClientID
        ]
        
        var urlComponents: URLComponents? = URLComponents(url: self.mainUrl.appendingPathComponent("/api/refresh"),
                                                          resolvingAgainstBaseURL: false)
        urlComponents?.queryItems = []
        for param in addParamsForRefresh {
            if let value = param.value as? String {
                let item = URLQueryItem(name: param.key, value: value)
                urlComponents?.queryItems?.append(item)
            }
        }
        
        AF.request(urlComponents ?? self.mainUrl.appendingPathComponent("/api/refresh"),
                   method: .post,
                   parameters: parametersForLogin,
                   encoding: JSONEncoding.default,
                   headers: headersForLogin).responseDecodable(decoder: decoder) { (loginResponse: AFDataResponse<Token> ) in
            switch loginResponse.result {
            case .success(let value):
                self.defaultsManager.accessToken = value.accessToken
                self.defaultsManager.tokenExpireDate = Date().addingTimeInterval(TimeInterval(value.expiresIn))
                self.defaultsManager.refreshToken = value.refreshToken
                result(loginResponse)
            case .failure:
                APIRouter.nowIsRefreshing = false
                self.logOut()
            }
                    
        }

    }
    
    func makeRequest<T: Decodable>(url: String,
                                   method: HTTPMethod = .get,
                                   parameters: Parameters? = nil,
                                   encoding: ParameterEncoding = JSONEncoding.default,
                                   additionalQueryParams: Parameters? = nil,
                                   headers: HTTPHeaders? = nil,
                                   completion: @escaping (AFDataResponse<T>) -> Void) -> DataRequest? {
        self.cleanCache()
       
        var requestHeaders: HTTPHeaders = HTTPHeaders()
       
       if let token = defaultsManager.accessToken, url != "/api/login" {
           if defaultsManager.changeTokenLikeABoss {
            requestHeaders = [Constant.HTTPHeaderField.authorization: "Bearer 123"]
           } else {
               requestHeaders = [Constant.HTTPHeaderField.authorization: "Bearer \(token)"]
           }
           
           if defaultsManager.changeTokenLikeABoss {
               defaultsManager.changeTokenLikeABoss = false
           }
       }
       
       if let headers = self.lastRequest?.headers {
           headers.forEach { requestHeaders[$0.name] = $0.value }
       } else {
           headers?.forEach { requestHeaders[$0.name] = $0.value }
       }

       if url == "/api/login" {
           requestHeaders.remove(name: Constant.HTTPHeaderField.authorization)
       }
       #if DEBUG
           print("""
               --------------------------------------------
               \(requestHeaders)
               --------------------------------------------
               """)
       #endif
       var urlComponents = URLComponents(url: self.mainUrl.appendingPathComponent(url), resolvingAgainstBaseURL: false)
       if let additionalQueryParams = additionalQueryParams {
           urlComponents?.queryItems = []
           for param in additionalQueryParams {
               if let value = param.value as? String {
                   let item = URLQueryItem(name: param.key, value: value)
                   urlComponents?.queryItems?.append(item)
               }
           }
       }
        debugPrint(urlComponents?.url?.absoluteURL ?? "")
       debugPrint(requestHeaders)
       //first try
   
       return AF.request(urlComponents?.url?.absoluteURL ?? self.mainUrl.appendingPathComponent(url),
                             method: method,
                             parameters: parameters,
                             encoding: encoding,
                             headers: requestHeaders)
           .responseDecodable(decoder: decoder) { (response: AFDataResponse<T>) in
            #if DEBUG
                debugPrint(response)
                print("\(String(describing: response.response?.statusCode))\(String(describing: response.response?.url))")
                if let body = response.request?.httpBody {
                    debugPrint(NSString(data: body, encoding: String.Encoding.utf8.rawValue) as Any)
                }
            #endif

            if response.response?.statusCode == 401 {
                self.defaultsManager.accessToken = nil
                self.defaultsManager.tokenExpireDate = nil
            }

            completion(response)
        }

    }
    
    func saveFirstRequest(url: String,
                          method: HTTPMethod = .get,
                          parameters: Parameters? = nil,
                          encoding: ParameterEncoding = JSONEncoding.default,
                          headers: HTTPHeaders? = nil) {
        self.lastRequest = ModalRequest()
        self.lastRequest?.path = url
        self.lastRequest?.method = method
        self.lastRequest?.parameters = parameters
        self.lastRequest?.encoding = encoding
        self.lastRequest?.headers = headers
        if let token = self.defaultsManager.accessToken {
            self.lastRequest?.headers?[Constant.HTTPHeaderField.authorization] = "Bearer \(token)"
        }
    }
    
    private func saveRequest(_ block: @escaping () -> Void) {
        savedRequests.append( DispatchWorkItem {
            block()
        })
    }

    private func executeAllSavedRequests() {
        savedRequests.forEach({ DispatchQueue.global().async(execute: $0) })
        savedRequests.removeAll()
    }
    
    func logOut() {
        self.authAPI.logout { (_) in }
        if let firebaseToken = defaultsManager.firebaseToken {
            self.authAPI.removeDeviceForNotifications(deviceId: firebaseToken) { (_) in }
            self.defaultsManager.firebaseToken = nil
        }
        if !(UIApplication.topViewController() is LoginVC) {
            Crashlytics().logMessage(name: Constant.AnalyticsEvents.logOut)
            self.defaultsManager.accessToken = nil
            self.defaultsManager.tokenExpireDate = nil
            self.defaultsManager.refreshToken = nil
            self.defaultsManager.currentUserEmail = nil
            self.defaultsManager.currentUser = nil
            if let appDelegate = UIApplication.shared.delegate as? AppDelegate {
                appDelegate.manageInitVC()
            }
        }
    }
    
    func cleanCache() {
        let cookieStore = HTTPCookieStorage.shared
        for cookie in cookieStore.cookies ?? [] {
            cookieStore.deleteCookie(cookie)
        }
        URLCache.shared.removeAllCachedResponses()
    }
    
    func isBlackListRequest(url: String) -> Bool {
        return url != "/api/login" && url != "/api/logout" && url != "/api/mobile/client/version/verify"
    }
    
}
