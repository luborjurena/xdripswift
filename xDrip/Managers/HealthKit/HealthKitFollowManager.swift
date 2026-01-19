//
//  HealthKitFollowManager.swift
//  xdrip
//
//  Created for xDrip project.
//

import AudioToolbox
import AVFoundation
import Foundation
import HealthKit
import os

/// Instance of this class will do the follower functionality by reading glucose data from Apple Health.
/// Just make an instance, it will listen to the settings, do the regular download if needed.
class HealthKitFollowManager: NSObject {
    
    // MARK: - Private Properties
    
    /// to solve problem that sometimes UserDefaults key value changes is triggered twice for just one change
    private let keyValueObserverTimeKeeper: KeyValueObserverTimeKeeper = .init()
    
    /// for logging
    private var log = OSLog(subsystem: ConstantsLog.subSystem, category: ConstantsLog.categoryHealthKitFollowManager)
    
    /// reference to CoreDataManager
    private var coreDataManager: CoreDataManager
    
    /// reference to BgReadingsAccessor
    private var bgReadingsAccessor: BgReadingsAccessor
    
    /// delegate to pass back glucose data
    private(set) weak var followerDelegate: FollowerDelegate?
    
    /// AVAudioPlayer to use for keep-alive
    private var audioPlayer: AVAudioPlayer?
    
    /// constant for key in ApplicationManager.shared.addClosureToRunWhenAppWillEnterForeground - create playsoundtimer
    private let applicationManagerKeyResumePlaySoundTimer = "HealthKitFollowManager-ResumePlaySoundTimer"
    
    /// constant for key in ApplicationManager.shared.addClosureToRunWhenAppDidEnterBackground - invalidate playsoundtimer
    private let applicationManagerKeySuspendPlaySoundTimer = "HealthKitFollowManager-SuspendPlaySoundTimer"
    
    /// closure to call when downloadtimer needs to be invalidated
    private var invalidateDownLoadTimerClosure: (() -> Void)?
    
    /// timer for playsound
    private var playSoundTimer: RepeatingTimer?
    
    /// HealthKit store
    private lazy var healthStore = HKHealthStore()
    
    /// Blood glucose quantity type
    private var bloodGlucoseType: HKQuantityType?
    
    /// Is HealthKit initialized and authorized for reading?
    private var healthKitReadAuthorized = false
    
    /// HKObserverQuery for background updates
    private var observerQuery: HKObserverQuery?
    
    // MARK: - Initializer
    
    /// Initializer
    /// - Parameters:
    ///   - coreDataManager: The CoreDataManager instance for BG reading storage.
    ///   - followerDelegate: The delegate to receive BG reading updates.
    public init(coreDataManager: CoreDataManager, followerDelegate: FollowerDelegate) {
        self.coreDataManager = coreDataManager
        self.bgReadingsAccessor = BgReadingsAccessor(coreDataManager: coreDataManager)
        self.followerDelegate = followerDelegate
        
        // set up audioplayer for keep-alive
        if let url = Bundle.main.url(forResource: ConstantsSuspensionPrevention.soundFileName, withExtension: "") {
            do {
                self.audioPlayer = try AVAudioPlayer(contentsOf: url)
            } catch {
                // will be logged after super.init
            }
        }
        
        super.init()
        
        // Initialize HealthKit for reading
        initializeHealthKitForReading()
        
        // Add observers for UserDefaults changes
        UserDefaults.standard.addObserver(self, forKeyPath: UserDefaults.Key.isMaster.rawValue, options: .new, context: nil)
        UserDefaults.standard.addObserver(self, forKeyPath: UserDefaults.Key.followerDataSourceType.rawValue, options: .new, context: nil)
        UserDefaults.standard.addObserver(self, forKeyPath: UserDefaults.Key.followerBackgroundKeepAliveType.rawValue, options: .new, context: nil)
        
        // Start or stop follow mode based on current settings
        verifyUserDefaultsAndStartOrStopFollowMode()
    }
    
    // MARK: - Deinitializer
    
    deinit {
        // Remove UserDefaults observers
        UserDefaults.standard.removeObserver(self, forKeyPath: UserDefaults.Key.isMaster.rawValue)
        UserDefaults.standard.removeObserver(self, forKeyPath: UserDefaults.Key.followerDataSourceType.rawValue)
        UserDefaults.standard.removeObserver(self, forKeyPath: UserDefaults.Key.followerBackgroundKeepAliveType.rawValue)
        
        // Stop keep-alive
        disableSuspensionPrevention()
        
        // Invalidate download timer
        invalidateDownLoadTimerClosure?()
        
        // Stop observer query
        if let observerQuery = observerQuery {
            healthStore.stop(observerQuery)
        }
    }
    
    // MARK: - Public Functions
    
    /// Creates a BgReading object from a FollowerBgReading (Apple Health download).
    /// - Parameter followGlucoseData: The glucose data from Apple Health.
    /// - Returns: A new BgReading (not saved in Core Data).
    public func createBgReading(followGlucoseData: FollowerBgReading) -> BgReading {
        trace("Creating BgReading for timestamp: %{public}@, sgv: %{public}@", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .debug, String(describing: followGlucoseData.timeStamp), String(describing: followGlucoseData.sgv))
        
        let deviceName = ConstantsHomeView.applicationName + " (Apple Health)"
        
        let bgReading = BgReading(
            timeStamp: followGlucoseData.timeStamp,
            sensor: nil,
            calibration: nil,
            rawData: followGlucoseData.sgv,
            deviceName: deviceName,
            nsManagedObjectContext: self.coreDataManager.mainManagedObjectContext
        )
        
        bgReading.calculatedValue = followGlucoseData.sgv
        
        let (calculatedValueSlope, hideSlope) = findSlope()
        bgReading.calculatedValueSlope = calculatedValueSlope
        bgReading.hideSlope = hideSlope
        
        return bgReading
    }
    
    /// Download recent readings from Apple Health
    @objc public func download() {
        trace("in download", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .info)
        
        // Trigger Nightscout sync if needed
        if (UserDefaults.standard.timeStampLatestNightscoutSyncRequest ?? .distantPast).timeIntervalSinceNow < -15 {
            trace("    setting nightscoutSyncRequired to true", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .info)
            UserDefaults.standard.timeStampLatestNightscoutSyncRequest = .now
            UserDefaults.standard.nightscoutSyncRequired = true
        }
        
        guard !UserDefaults.standard.isMaster else {
            trace("    not follower, returning", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .info)
            return
        }
        
        guard UserDefaults.standard.followerDataSourceType == .appleHealth else {
            trace("    followerDataSourceType is not Apple Health", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .info)
            return
        }
        
        guard healthKitReadAuthorized else {
            trace("    HealthKit not authorized for reading", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .info)
            return
        }
        
        // Fetch glucose readings from Apple Health
        fetchGlucoseReadings { [weak self] readings in
            guard let self = self else { return }
            
            DispatchQueue.main.async {
                if !readings.isEmpty {
                    trace("    downloaded %{public}@ readings from Apple Health", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .info, readings.count.description)
                    
                    var followGlucoseDataArray = readings
                    self.followerDelegate?.followerInfoReceived(followGlucoseDataArray: &followGlucoseDataArray)
                } else {
                    trace("    no readings downloaded from Apple Health", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .info)
                }
                
                // Schedule next download
                self.scheduleNewDownload()
            }
        }
    }
    
    // MARK: - Private Functions
    
    /// Initialize HealthKit for reading blood glucose data
    private func initializeHealthKitForReading() {
        guard HKHealthStore.isHealthDataAvailable() else {
            trace("HealthKit is not available on this device", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .error)
            return
        }
        
        bloodGlucoseType = HKObjectType.quantityType(forIdentifier: .bloodGlucose)
        
        guard bloodGlucoseType != nil else {
            trace("Failed to create blood glucose type", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .error)
            return
        }
        
        // Check current authorization status - note: we cannot check read authorization status directly
        // We need to request authorization and handle it when user enables Apple Health as follower source
        healthKitReadAuthorized = true // Assume authorized, will fail gracefully on fetch if not
        
        trace("HealthKit initialized for reading", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .info)
    }
    
    /// Request HealthKit authorization for reading blood glucose
    public func requestReadAuthorization(completion: @escaping (Bool) -> Void) {
        guard let bloodGlucoseType = bloodGlucoseType else {
            completion(false)
            return
        }
        
        let readTypes: Set<HKObjectType> = [bloodGlucoseType]
        
        healthStore.requestAuthorization(toShare: nil, read: readTypes) { [weak self] success, error in
            guard let self = self else { return }
            
            if let error = error {
                trace("HealthKit read authorization error: %{public}@", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .error, error.localizedDescription)
            }
            
            self.healthKitReadAuthorized = success
            
            if success {
                trace("HealthKit read authorization granted", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .info)
                
                // Set up background observer query
                DispatchQueue.main.async {
                    self.setupBackgroundObserver()
                }
            }
            
            completion(success)
        }
    }
    
    /// Set up HKObserverQuery for background updates
    private func setupBackgroundObserver() {
        guard let bloodGlucoseType = bloodGlucoseType else { return }
        
        // Stop existing observer if any
        if let existingQuery = observerQuery {
            healthStore.stop(existingQuery)
        }
        
        let query = HKObserverQuery(sampleType: bloodGlucoseType, predicate: nil) { [weak self] _, completionHandler, error in
            guard let self = self else {
                completionHandler()
                return
            }
            
            if let error = error {
                trace("Observer query error: %{public}@", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .error, error.localizedDescription)
                completionHandler()
                return
            }
            
            // New data available, trigger download
            DispatchQueue.main.async {
                self.download()
            }
            
            completionHandler()
        }
        
        observerQuery = query
        healthStore.execute(query)
        
        // Enable background delivery
        healthStore.enableBackgroundDelivery(for: bloodGlucoseType, frequency: .immediate) { [weak self] success, error in
            guard let self = self else { return }
            
            if let error = error {
                trace("Failed to enable background delivery: %{public}@", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .error, error.localizedDescription)
            } else if success {
                trace("Background delivery enabled for blood glucose", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .info)
            }
        }
    }
    
    /// Fetch glucose readings from Apple Health
    /// - Parameter completion: Completion handler with array of FollowerBgReading
    private func fetchGlucoseReadings(completion: @escaping ([FollowerBgReading]) -> Void) {
        guard let bloodGlucoseType = bloodGlucoseType else {
            completion([])
            return
        }
        
        // Get readings from the last 24 hours
        let now = Date()
        let startDate = now.addingTimeInterval(-24 * 60 * 60)
        
        // Check if we have recent readings to avoid fetching too much data
        if let lastReading = bgReadingsAccessor.last(forSensor: nil) {
            // If we have a recent reading, only fetch from slightly before that
            let adjustedStartDate = lastReading.timeStamp.addingTimeInterval(-5 * 60) // 5 minutes before last reading
            let predicate = HKQuery.predicateForSamples(withStart: adjustedStartDate, end: now, options: .strictStartDate)
            executeGlucoseQuery(type: bloodGlucoseType, predicate: predicate, limit: 100, completion: completion)
        } else {
            // No readings yet, fetch last 24 hours
            let predicate = HKQuery.predicateForSamples(withStart: startDate, end: now, options: .strictStartDate)
            executeGlucoseQuery(type: bloodGlucoseType, predicate: predicate, limit: 288, completion: completion)
        }
    }
    
    /// Execute the actual HealthKit query
    private func executeGlucoseQuery(type: HKQuantityType, predicate: NSPredicate, limit: Int, completion: @escaping ([FollowerBgReading]) -> Void) {
        let sortDescriptor = NSSortDescriptor(key: HKSampleSortIdentifierStartDate, ascending: false)
        
        let query = HKSampleQuery(
            sampleType: type,
            predicate: predicate,
            limit: limit,
            sortDescriptors: [sortDescriptor]
        ) { [weak self] _, samples, error in
            guard let self = self else {
                completion([])
                return
            }
            
            if let error = error {
                trace("HealthKit query error: %{public}@", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .error, error.localizedDescription)
                completion([])
                return
            }
            
            guard let samples = samples as? [HKQuantitySample] else {
                completion([])
                return
            }
            
            // Update last connection timestamp
            UserDefaults.standard.timeStampOfLastFollowerConnection = Date()
            
            // Convert samples to FollowerBgReading
            let readings = samples.compactMap { sample -> FollowerBgReading? in
                // Convert to mg/dL
                let mgdLUnit = HKUnit(from: "mg/dL")
                let value = sample.quantity.doubleValue(for: mgdLUnit)
                
                // Filter out readings that may have been written by this app
                // by checking the source bundle identifier
                if let bundleId = Bundle.main.bundleIdentifier,
                   sample.sourceRevision.source.bundleIdentifier == bundleId {
                    return nil
                }
                
                return FollowerBgReading(timeStamp: sample.startDate, sgv: value)
            }
            
            // Sort by timestamp (newest first)
            let sortedReadings = readings.sorted { $0.timeStamp > $1.timeStamp }
            
            completion(sortedReadings)
        }
        
        healthStore.execute(query)
    }
    
    /// Calculate slope from recent readings
    private func findSlope() -> (calculatedValueSlope: Double, hideSlope: Bool) {
        var hideSlope = true
        var calculatedValueSlope = 0.0
        
        let last2Readings = bgReadingsAccessor.getLatestBgReadings(limit: 3, howOld: 1, forSensor: nil, ignoreRawData: true, ignoreCalculatedValue: false)
        
        if last2Readings.count >= 2 {
            let (slope, hide) = last2Readings[0].calculateSlope(lastBgReading: last2Readings[1])
            calculatedValueSlope = slope
            hideSlope = hide
        }
        
        return (calculatedValueSlope, hideSlope)
    }
    
    /// Schedule a new download
    private func scheduleNewDownload() {
        guard UserDefaults.standard.followerBackgroundKeepAliveType != .heartbeat else { return }
        
        // Invalidate existing timer
        invalidateDownLoadTimerClosure?()
        invalidateDownLoadTimerClosure = nil
        
        trace("in scheduleNewDownload", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .info)
        
        // Schedule timer for 60 seconds
        let downloadTimer = Timer.scheduledTimer(timeInterval: 60, target: self, selector: #selector(download), userInfo: nil, repeats: false)
        
        invalidateDownLoadTimerClosure = {
            downloadTimer.invalidate()
        }
    }
    
    /// Disable suspension prevention
    private func disableSuspensionPrevention() {
        if let playSoundTimer = playSoundTimer {
            playSoundTimer.suspend()
        }
        
        ApplicationManager.shared.removeClosureToRunWhenAppDidEnterBackground(key: applicationManagerKeyResumePlaySoundTimer)
        ApplicationManager.shared.removeClosureToRunWhenAppWillEnterForeground(key: applicationManagerKeySuspendPlaySoundTimer)
    }
    
    /// Enable suspension prevention
    private func enableSuspensionPrevention() {
        guard UserDefaults.standard.followerBackgroundKeepAliveType.shouldKeepAlive else {
            trace("not enabling suspension prevention as keep-alive type is: %{public}@", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .info, UserDefaults.standard.followerBackgroundKeepAliveType.description)
            return
        }
        
        let interval = UserDefaults.standard.followerBackgroundKeepAliveType == .normal
            ? ConstantsSuspensionPrevention.intervalNormal
            : ConstantsSuspensionPrevention.intervalAggressive
        
        playSoundTimer = RepeatingTimer(timeInterval: TimeInterval(Double(interval))) { [weak self] in
            guard let self = self else { return }
            
            trace("in eventhandler checking if audioplayer exists", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .info)
            
            if let audioPlayer = self.audioPlayer, !audioPlayer.isPlaying {
                trace("playing audio every %{public}@ seconds for Apple Health keep-alive", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .info, interval.description)
                audioPlayer.play()
            }
        }
        
        ApplicationManager.shared.addClosureToRunWhenAppDidEnterBackground(key: applicationManagerKeyResumePlaySoundTimer) { [weak self] in
            guard let self = self else { return }
            
            if UserDefaults.standard.followerBackgroundKeepAliveType.shouldKeepAlive {
                self.playSoundTimer?.resume()
                
                if let audioPlayer = self.audioPlayer, !audioPlayer.isPlaying {
                    audioPlayer.play()
                }
            }
        }
        
        ApplicationManager.shared.addClosureToRunWhenAppWillEnterForeground(key: applicationManagerKeySuspendPlaySoundTimer) { [weak self] in
            guard let self = self else { return }
            self.playSoundTimer?.suspend()
        }
    }
    
    /// Verify UserDefaults and start or stop follow mode
    private func verifyUserDefaultsAndStartOrStopFollowMode() {
        if !UserDefaults.standard.isMaster && UserDefaults.standard.followerDataSourceType == .appleHealth {
            // Enable suspension prevention immediately if needed (don't wait for auth callback)
            // This is critical for background operation
            if UserDefaults.standard.followerBackgroundKeepAliveType.shouldKeepAlive {
                enableSuspensionPrevention()
            } else {
                disableSuspensionPrevention()
            }
            
            // Request authorization and start downloading
            requestReadAuthorization { [weak self] success in
                guard let self = self else { return }
                
                DispatchQueue.main.async {
                    if success {
                        // Start initial download
                        self.download()
                    } else {
                        trace("HealthKit authorization not granted", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .error)
                    }
                }
            }
        } else {
            // Disable suspension prevention
            disableSuspensionPrevention()
            
            // Invalidate download timer
            invalidateDownLoadTimerClosure?()
            
            // Stop observer query
            if let observerQuery = observerQuery {
                healthStore.stop(observerQuery)
                self.observerQuery = nil
            }
        }
    }
    
    // MARK: - KVO
    
    override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey: Any]?, context: UnsafeMutableRawPointer?) {
        guard let keyPath = keyPath,
              let keyPathEnum = UserDefaults.Key(rawValue: keyPath) else { return }
        
        switch keyPathEnum {
        case .isMaster, .followerDataSourceType:
            if keyValueObserverTimeKeeper.verifyKey(forKey: keyPathEnum.rawValue, withMinimumDelayMilliSeconds: 200) {
                verifyUserDefaultsAndStartOrStopFollowMode()
            }
            
        case .followerBackgroundKeepAliveType:
            // Only react if we're in Apple Health follower mode
            if !UserDefaults.standard.isMaster && UserDefaults.standard.followerDataSourceType == .appleHealth {
                if keyValueObserverTimeKeeper.verifyKey(forKey: keyPathEnum.rawValue, withMinimumDelayMilliSeconds: 200) {
                    trace("followerBackgroundKeepAliveType changed, updating suspension prevention", log: self.log, category: ConstantsLog.categoryHealthKitFollowManager, type: .info)
                    
                    if UserDefaults.standard.followerBackgroundKeepAliveType.shouldKeepAlive {
                        enableSuspensionPrevention()
                    } else {
                        disableSuspensionPrevention()
                    }
                }
            }
            
        default:
            break
        }
    }
}
