##################### Libraries #####################
library(randomForest)
library(ranger)
library(plyr)
library(gbm)
library(caret)
library(pROC)

#Parallelization
library(parallel)
library(doParallel)


##################### Data Exploration #####################

all_data <- read.csv('mal_and_benign_traces.csv', header=T) #reading in the data

#First run to check variable importance
set.seed(12)
rf1 <- randomForest(all_data[,-1], all_data[,1], mtry = 2, ntree = 300)
var_imp <- varImpPlot(rf1, sort = TRUE, main = "Variable Importance")
  

#Mean interval Distribution
boxplot(all_data[all_data[,"mean_intvl"]<40000,"mean_intvl"]~all_data[all_data[,"mean_intvl"]<40000,"Malicious"],
        notch=FALSE, 
        col=(c("darkgreen","red")),
        main="Mean Interval distribution", xlab = "Non Malicious/Malacious", ylab = "Mean Interval")

#Mean Source Packets
boxplot(all_data[all_data[,"mean_src_pkts"]<100,"mean_src_pkts"]~all_data[all_data[,"mean_src_pkts"]<100,"Malicious"],
        notch=FALSE, 
        col=(c("darkgreen","red")),
        main="Mean Source Packets Distribution", xlab = "Non Malicious/Malacious", ylab = "Mean Source Packets")

#Mean Duration
boxplot(all_data[all_data[,"mean_duration"],"mean_duration"]~all_data[all_data[,"mean_duration"],"Malicious"],
        notch=FALSE, 
        col=(c("darkgreen","red")),
        main="Mean Duration Distribution", xlab = "Non Malicious/Malacious", ylab = "Mean Duration")





##################### Splitting Data #####################
set.seed(134)

train_index <- sample(1:nrow(all_data), 3000, replace= FALSE)

caret_data <- all_data[train_index,-c(2:6)]
caret_test <- all_data[-train_index,-c(2:6)]




##################### Caret Implementation of Radial SVM ##################### 

grid_radial <- expand.grid(sigma = c(0,0.01, 0.1,1), C = c(0.01, 0.1,1, 2,5))

svm_Radial <- train(as.factor(Malicious) ~., data = caret_data, method = "svmRadial",
                    trControl=control,
                    preProcess = c("center"),
                    tuneGrid = grid_radial,
                    tuneLength = 10)

print(svm_Radial)

#test
test_pred_svmr <- predict(svm_Radial, newdata = caret_test[,-1])
confusionMatrix(test_pred_svmr, as.factor(caret_test[,1]))

##################### SVM-R Results #####################
# Confusion Matrix and Statistics
# 
#               Reference
# Prediction    0    1
#           0 1058  207
#           1    0   10
# 
# Accuracy : 0.8376          
# 95% CI : (0.8162, 0.8575)
# Sensitivity : 1.00000         
# Specificity : 0.04608         
# Pos Pred Value : 0.83636 (Correct Benign)         
# Neg Pred Value : 1.00000  (Correct Malicious)      

#Balanced Accuracy : 0.52304 


##################### Caret Implementation of Random Forest #####################

#Create custom RF function for grid search in Caret 
customRF <- list(type = "Classification", library = "randomForest", loop = NULL)
customRF$parameters <- data.frame(parameter = c("mtry", "ntree"), class = rep("numeric", 2), label = c("mtry", "ntree"))
customRF$grid <- function(x, y, len = NULL, search = "grid") {}
customRF$fit <- function(x, y, wts, param, lev, last, weights, classProbs, ...) {
  randomForest(x, y, mtry = param$mtry, ntree=param$ntree, ...)
}
customRF$predict <- function(modelFit, newdata, preProc = NULL, submodels = NULL)
  predict(modelFit, newdata)
customRF$prob <- function(modelFit, newdata, preProc = NULL, submodels = NULL)
  predict(modelFit, newdata, type = "prob")
customRF$sort <- function(x) x[order(x[,1]),]
customRF$levels <- function(x) x$classes

#Start clusters
cluster <- makeCluster(detectCores())
registerDoParallel(cluster)

#Caret implementation of customRF
control <- trainControl(method="repeatedcv", number=10, repeats=3, search="grid", allowParallel = TRUE)
set.seed(3)
metric <- "Accuracy"
tunegrid <- expand.grid(.mtry=c(2, 6, 33), .ntree=c(100, 200, 300, 500))
rf_gridsearch <- train(as.factor(Malicious) ~., data=caret_data, method= customRF, 
                       metric=metric, tuneGrid = tunegrid, trControl=control)
print(rf_gridsearch)
plot(rf_gridsearch)


#Create randomforest on optimum mtry and ntrees
crf <- randomForest(caret_data[,-1], as.factor(caret_data[,1]), mtry = 6, ntree = 200)

#test
test_pred_crf <- predict(crf, newdata = caret_test[,-1])
confusionMatrix(test_pred_crf, as.factor(caret_test[,1]))

##################### Random Forest Results #####################
# Confusion Matrix and Statistics
# 
#              Reference
# Prediction    0    1
#            0 1056    6
#            1    2  211
# 
# Accuracy : 0.9937          
# 95% CI : (0.9877, 0.9973)
# No Information Rate : 0.8298          
# P-Value [Acc > NIR] : <2e-16          

# Sensitivity : 0.9981          
# Specificity : 0.9724          
# Pos Pred Value : 0.9944 (Correct Benign)         
# Neg Pred Value : 0.9906 (Correct Malicious)          

# Balanced Accuracy : 0.9852          



