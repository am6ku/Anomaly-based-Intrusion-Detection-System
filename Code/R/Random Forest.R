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


##################### Reading & Splitting Data #####################

all_data <- read.csv('mal_and_benign_traces.csv', header=T) #reading in the data

colnames(all_data)[20:29] <- paste("src", colnames(all_data)[20:29], sep = "_")
colnames(all_data)[30:39] <- paste("dest", colnames(all_data)[30:39], sep = "_")

set.seed(134)

train_index <- sample(1:nrow(all_data), 3000, replace= FALSE)

caret_data <- all_data[train_index,-c(2:6)]
caret_test <- all_data[-train_index,-c(2:6)]


##################### Data Exploration #####################

#First run to check variable importance
set.seed(12)
rf1 <- randomForest(all_data[,-c(1:6)], all_data[,1], mtry = 2, ntree = 300)
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




##################### Caret Implementation of Radial SVM ##################### 

#Start clusters
cluster <- makeCluster(detectCores())
registerDoParallel(cluster)


control <- trainControl(method="repeatedcv", number=10, 
                        summaryFunction=twoClassSummary, classProbs=T,
                        savePredictions = T,allowParallel = TRUE)


svm_Radial <- train(as.factor(Malicious) ~., data = caret_data, method = "svmRadial",
                    trControl=control,
                    preProcess = c("center"),
                    tuneLength = 10)

print(svm_Radial)

# Select a parameter setting
selectedIndices <- svm_Radial$pred$C == 32


g <- ggplot(svm_Radial$pred[selectedIndices, ], aes(m = Yes,d=factor(obs, levels = c("Yes", "No")))) + 
  geom_roc(n.cuts=0) + 
  coord_equal() +
  style_roc()

g + annotate("text", y=0.25, x=0.75,label=paste("AUC =", round((calc_auc(g))$AUC, 4)))


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
#F1 = 0.4554445

#F1 AUC and ROC

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


#Caret implementation of customRF
set.seed(3)
metric <- "ROC"
tunegrid <- expand.grid(.mtry=c(2, 6, 33), .ntree=c(100, 200, 300, 500))
rf_gridsearch <- train(as.factor(Malicious) ~., data=caret_data, method= customRF, 
                       metric="ROC", tuneGrid = tunegrid, trControl=control)
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
#F1 = 0.4962482

# Balanced Accuracy : 0.9852          

#Different malware famililes
#Percent parameters used

####################################ROC CURVE####################################
# Calculating AUC
auc <- roc(ifelse(caret_test[,1]=="0",1,0), ifelse(test_pred_svmr=="0",1,0))
auc1 <- roc(ifelse(caret_test[,1]=="0",1,0), ifelse(test_pred_crf=="0",1,0))
print(auc$auc) # 0.5
print(auc1$auc) # 0.4983

# calculating the values for ROC curve
pred <- prediction(as.numeric(as.character(test_pred_svmr)), as.numeric(caret_test$Malicious))
perf <- performance(pred, measure = "tpr", x.measure = "fpr")
pred1 <- prediction(as.numeric(as.character(test_pred_crf)), as.numeric(caret_test$Malicious))
perf1 <- performance(pred1, measure = "tpr", x.measure = "fpr")
# changing params for the ROC plot - width, etc
par(mar=c(5,5,2,2),xaxs = "i",yaxs = "i",cex.axis=1.3,cex.lab=1.4)
# plotting the ROC curve
plot(perf, col = "blue")
plot(perf1, add = TRUE, col = "red")
# calculating AUC
auc <- performance(pred, "auc")
auc # 0.5
auc1 <- performance(pred1, "auc")
auc1 # 0.4983051
